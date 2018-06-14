/*
 * This file is part of the Hephaistos-AHA project.
 * Copyright (C) 2018  Tido Klaassen <tido_hephaistos@4gh.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <expat.h>
#include <expat-dom.h>
#include <klist.h>
#include <kref.h>
#include <hephaistos.h>
#include <avm_aha.h>
#include <sdkconfig.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/md5.h"

#define GPIO_HEAT       CONFIG_GPIO_HEAT
#define GPIO_LED        CONFIG_GPIO_LED

#define TWDT_TIMEOUT_S          300
#define TASK_RESET_PERIOD_S     5

static const char *TAG = "AHA";

static struct aha_cfg aha_cfg;
static SemaphoreHandle_t aha_cfg_lock = NULL;

static TimerHandle_t aha_timer = NULL;
static EventGroupHandle_t aha_event_group;
const int BIT_TIMER     = BIT0;
const int BIT_SUSPEND   = BIT1;
const int BIT_RELOAD    = BIT2;

static const char *HTTP_REQ = 
        "GET %s HTTP/1.0\r\n"
        "HOST: %s\r\n"
        "CONNECTION: keep-alive\r\n"
        "USER-AGENT: AVM UPnP/1.0 Client 1.0\r\n"
        "\r\n";

static const char *SID_CHECK = "/login_sid.lua?sid=%s";
static const char *SID_GET = "/login_sid.lua?username=%s&response=%s-%s";
static const char *HKR_REQ = "/webservices/homeautoswitch.lua?switchcmd=getdevicelistinfos&sid=%s";

#define HTTP_REQ_SIZE   1024

/* Pointer to current aha_data available through aha_data_get().
 * Once initialised, will always hold a pointer to a valid data set */
static struct aha_data *curr_aha_data = NULL;
static SemaphoreHandle_t aha_data_lock = NULL;

static struct aha_data *create_data(void)
{
    struct aha_data *data;

    data = calloc(sizeof(*data), 1);
    if(data == NULL){
        ESP_LOGE(TAG, "Out of memory for aha_data");
        goto err_out;
    }

    kref_init(&(data->ref_cnt));
    INIT_KLIST_HEAD(&(data->dev_head));
    INIT_KLIST_HEAD(&(data->grp_head));

err_out:
    return data;
}

static void release_data(struct kref *ref_cnt)
{
    struct aha_data *data;
    struct aha_device *device, *group, *tmp_dev, *tmp_grp;

    data = container_of(ref_cnt, struct aha_data, ref_cnt);

    klist_for_each_entry_safe(group, tmp_grp, &(data->grp_head), grp_list)
    {
        /* remove all devices from the group's member list */
        klist_for_each_entry_safe(device, tmp_dev, &(group->member_list), member_list)
        {
            klist_del(&(device->member_list));
            device->group = NULL;
        }

        /* remove group from group list */
        klist_del_init(&(group->grp_list));

        free(group);
    }

    klist_for_each_entry_safe(device, tmp_dev, &(data->dev_head), dev_list)
    {
        /* remove device from device list */
        klist_del(&(device->dev_list));
        free(device);
    }

    free(data);
}

struct auth_data
{
    char user[AHA_CFG_MAXLEN];
    char pass[AHA_CFG_MAXLEN];
    char realm[128];
    char nonce[128];
    char auth[128];
    char sid[128];
};

int gen_tr064_auth(struct auth_data *data)
{
    mbedtls_md5_context ctx;
    unsigned char md5sum[16];
    unsigned char md5str[33];
    unsigned int i;

    memset(data->auth, 0x0, sizeof(data->auth));

    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, (unsigned char *) data->user, strlen(data->user));
    mbedtls_md5_update(&ctx, (unsigned char *) ":", 1);
    mbedtls_md5_update(&ctx, (unsigned char *) data->realm, strlen(data->realm));
    mbedtls_md5_update(&ctx, (unsigned char *) ":", 1);
    mbedtls_md5_update(&ctx, (unsigned char *) data->pass, strlen(data->pass));
    mbedtls_md5_finish(&ctx, md5sum);
    mbedtls_md5_free(&ctx);

    for(i = 0; i < sizeof(md5sum); ++i){
        sprintf((char *) &(md5str[2 * i]), "%02x", md5sum[i]);
    }

    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, md5str, 32);
    mbedtls_md5_update(&ctx, (unsigned char *) ":", 1);
    mbedtls_md5_update(&ctx, (unsigned char *) data->nonce,
            strlen(data->nonce));
    mbedtls_md5_finish(&ctx, md5sum);
    mbedtls_md5_free(&ctx);

    memset(data->auth, 0x0, sizeof(data->auth));
    for(i = 0; i < sizeof(md5sum); ++i){
        sprintf(&(data->auth[2 * i]), "%02x", md5sum[i]);
    }

    return 0;
}

int gen_sid_auth(struct auth_data *data)
{
    mbedtls_md5_context ctx;
    unsigned char md5sum[16];
    unsigned char buf[256];
    unsigned int i, curr;

    memset(data->auth, 0x0, sizeof(data->auth));

    curr = 0;
    memset(buf, 0x0, sizeof(buf));
    for(i = 0;i < strlen(data->nonce);++i){
        buf[curr] = data->nonce[i];
        curr += 2;
    }

    buf[curr] = '-';
    curr += 2;

    for(i = 0; i < strlen(data->pass); ++i){
        buf[curr] = data->pass[i];
        curr += 2;
    }

    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, (unsigned char *) buf, curr);
    mbedtls_md5_finish(&ctx, md5sum);
    mbedtls_md5_free(&ctx);

    memset(data->auth, 0x0, sizeof(data->auth));
    for(i = 0; i < sizeof(md5sum); ++i){
        sprintf(&(data->auth[2 * i]), "%02x", md5sum[i]);
    }

    return 0;
}

static int do_http_req(char *host, char *service, dom_t **dom, const char *req)
{
    char buf[64];
    char *reply;
    size_t written, len;
    void *dom_parser;
    int body, result, sock;
    struct addrinfo hints;
    struct addrinfo *info;
    struct timeval receiving_timeout;

    sock = -1;
    info = NULL;
    memset(&hints, 0x0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    result = getaddrinfo(host, service, &hints, &info);

    if(result != 0 || info == NULL){
        ESP_LOGE(TAG, "DNS lookup failed err=%d %s info=%p", result, strerror(errno), info);
        goto err_out;
    }

    sock = socket(info->ai_family, info->ai_socktype, 0);
    if(sock < 0){
        ESP_LOGE(TAG, "... Failed to allocate socket.");
        result = sock;
        goto err_out;
    }

    result = connect(sock, info->ai_addr, info->ai_addrlen);
    if(result != 0){
        ESP_LOGE(TAG, "... socket connect failed result=%d", result);
        goto err_out;
    }

    written = 0;
    len = strlen(req);

    while(len > 0){
        result = write(sock, &(req[written]), len);
        if(result < 0){
            ESP_LOGE(TAG, "... socket send failed");
            goto err_out;
        }
        written += result;
        len -= result;
    }

    receiving_timeout.tv_sec = 5;
    receiving_timeout.tv_usec = 0;
    result = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &receiving_timeout,
            sizeof(receiving_timeout));
    if(result < 0){
        ESP_LOGE(TAG, "... failed to set socket receiving timeout");
        goto err_out;
    }

    body = 0;
    memset(buf, 0x42, 3);
    dom_parser = NULL;

    do{
        len = sizeof(buf) - 4;
        bzero(&(buf[3]), sizeof(buf) - 3);
        result = read(sock, (unsigned char *) &(buf[3]), len);
        if(result < 0){
            ESP_LOGE(TAG, "... failed to set socket receiving timeout");
            goto err_out;
        }

        /* connection closed? */
        if(result == 0){
            break;
        }

        len = result;

        if(body == 0){
            reply = strstr(buf, "\r\n\r\n");
            if(reply == NULL){
                memmove(buf, &(buf[len]), 3);
                continue;
            }
            reply += strlen("\r\n\r\n");
            len -= (reply - &(buf[3]));
            body = 1;
        }else{
            reply = &buf[3];
        }

        result = dom_parse_chunked_data(&dom_parser, dom, reply, len, 0);
    }while(1);

    result = dom_parse_chunked_data(&dom_parser, dom, NULL, 0, 1);

err_out:
    if(info != NULL){
        freeaddrinfo(info);
    }

    if(sock >= 0){
        close(sock);
    }

    if(result != 0 && *dom != NULL){
        dom_free(*dom);
        *dom = NULL;
    }

    return result;
}

static int parse_attr_ul(dom_t *dom, const char *name, unsigned long *dst)
{
    int result;
    const char *val;

    result = 0;
    val = dom_find_attr(dom->attr, name);
    if(val == NULL){
        result = -ENOENT;
        goto err_out;
    }

    errno = 0;
    *dst = strtoul(val, NULL, 10);
    result = errno;

err_out:
    return result;
}

static int __attribute__((unused)) parse_attr_long(dom_t *dom, const char *name, long *dst)
{
    int result;
    const char *val;

    result = 0;
    val = dom_find_attr(dom->attr, name);
    if(val == NULL){
        result = -ENOENT;
        goto err_out;
    }

    errno = 0;
    *dst = strtol(val, NULL, 10);
    result = errno;

err_out:
    return result;
}

static int parse_data_ul(dom_t *dom, const char *name, unsigned long *dst)
{
    int result;
    dom_t *node;
    char buf[32];

    result = 0;
    node = dom_find_node(dom, name);
    if(node == NULL){
        result = -ENOENT;
        goto err_out;
    }

    if(node->data_len >= (sizeof(buf) - 1)){
        result = -EINVAL;
        goto err_out;
    }

    memcpy(buf, node->data, node->data_len);
    buf[node->data_len] = '\0';

    errno = 0;
    *dst = strtoul(buf, NULL, 10);
    result = errno;

err_out:
    return result;
}

static int parse_data_long(dom_t *dom, const char *name, long *dst)
{
    int result;
    dom_t *node;
    char buf[32];

    result = 0;
    node = dom_find_node(dom, name);
    if(node == NULL){
        result = -ENOENT;
        goto err_out;
    }

    if(node->data_len >= (sizeof(buf) - 1)){
        result = -ENOSPC;
        goto err_out;
    }

    memcpy(buf, node->data, node->data_len);
    buf[node->data_len] = '\0';

    errno = 0;
    *dst = strtol(buf, NULL, 10);
    result = errno;

err_out:
    return result;
}

static int copy_attr_str(dom_t *dom, const char *name, char *dst, size_t len)
{
    const char *attr;
    size_t written;
    int result;

    result = 0;
    attr = dom_find_attr(dom->attr, name);
    if(attr == NULL){
        result = -ENOENT;
        goto err_out;
    }

    written = strlcpy(dst, attr, len);
    if(written >= len){
        result = -ENOSPC;
    }

err_out:
    return result;
}

static int copy_data_str(dom_t *dom, const char *name, char *dst, size_t len)
{
    dom_t *node;
    int result;

    result = 0;
    node = dom_find_node(dom, name);
    if(node == NULL){
        result = -ENOENT;
        goto err_out;
    }

    if(node->data_len >= len){
        result = -ENOSPC;
        goto err_out;
    }

    memcpy(dst, node->data, node->data_len);
    dst[node->data_len] = '\0';

err_out:
    return result;
}

static int parse_lock_state(dom_t *dom, const char *name, enum aha_lock_mode *state)
{
    unsigned long tmp;
    int result;

    result = parse_data_ul(dom, name, &tmp);
    if(result == 0){
        switch(tmp){
        case 0:
            *state = aha_lock_off;
            break;
        case 1:
            *state = aha_lock_on;
            break;
        default:
            result = -EINVAL;
            goto err_out;
        }
    }

err_out:
    return result;
}

static int parse_switch_state(dom_t *dom, const char *name, enum aha_switch_state *state)
{
    unsigned long tmp;
    int result;

    result = parse_data_ul(dom, name, &tmp);
    if(result == 0){
        switch(tmp){
        case 0:
            *state = aha_swstate_off;
            break;
        case 1:
            *state = aha_swstate_on;
            break;
        default:
            result = -EINVAL;
            goto err_out;
        }
    }

err_out:
    return result;
}

static int compare_data_str(dom_t *dom, const char *name, const char *val)
{
    dom_t *node;
    int result;

    result = 0;
    node = dom_find_node(dom, name);
    if(node == NULL){
        result = -ENOENT;
        goto err_out;
    }

    if(strncasecmp(val, node->data, node->data_len) != 0){
        result = 1;
    }

err_out:
    return result;
}

static int parse_switch_mode(dom_t *dom, const char *name, enum aha_switch_mode *mode)
{
    int result;

    result = compare_data_str(dom, name, "auto");
    if(result < 0){
        result = -EINVAL;
        goto err_out;
    } else if(result == 0){
        *mode = aha_switch_auto;
        goto err_out;
    }

    result = compare_data_str(dom, name, "manuell");
    if(result < 0){
        result = -EINVAL;
        goto err_out;
    } else if(result == 0){
        *mode = aha_switch_manual;
        goto err_out;
    }

    result = -ENOENT;

err_out:
    return result;
}

static int parse_group_entry(dom_t *dom, struct aha_device *entry)
{
    dom_t *node;
    char buf[AHA_ENTRY_LEN];
    char *tok, *saveptr;
    unsigned long val;
    int result;

    result = 0;
    node = dom_find_node(dom, "groupinfo");
    if(node == NULL){
        goto err_out;
    }

    node = node->child;

    result = parse_data_ul(node, "masterdeviceid", &(entry->grp.master_dev));
    if(result != 0 && result != -ENOENT){
        ESP_LOGE(TAG, "Parsing masterdeviceid failed for entry %s", entry->name);
        goto err_out;
    }
    result = 0;

    result = copy_data_str(node, "members", buf, sizeof(buf));
    if(result != 0){
        ESP_LOGE(TAG, "Copying member string failed for entry %s", entry->name);
        result = -EINVAL;
        goto err_out;
    }

    tok = strtok_r(buf, ",", &saveptr);
    while(tok != NULL && entry->grp.member_cnt < ARRAY_SIZE(entry->grp.members)){
        errno = 0;
        val = strtoul(tok, NULL, 10);
        if(errno != 0){
            ESP_LOGE(TAG, "Error parsing group members for entry %s", entry->name);
            result = errno;
            goto err_out;
        }

        entry->grp.members[entry->grp.member_cnt] = val;
        ++entry->grp.member_cnt;
        tok = strtok_r(NULL, ",", &saveptr);
    }

    entry->grp.present = true;

err_out:
    return result;
}

static int parse_hkr_entry(dom_t *dom, struct aha_device *entry)
{
    dom_t *node;
    int result;

    result = 0;
    node = dom_find_node(dom, "hkr");
    if(node == NULL){
        goto err_out;
    }

    node = node->child;

    result = parse_data_ul(node, "tist", &(entry->hkr.act_temp));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing actual temperature for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "tsoll", &(entry->hkr.set_temp));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing set temperature for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "komfort", &(entry->hkr.comfort_temp));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing comfort temperature for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "absenk", &(entry->hkr.eco_temp));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing eco temperature for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "errorcode", &(entry->hkr.error));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing error code for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "batterylow", &(entry->hkr.batt_low));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing battery status for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "endperiod", &(entry->hkr.next_change));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing next change time for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "tchange", &(entry->hkr.next_temp));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing next change temperature for entry %s", entry->name);
        goto err_out;
    }

    result = parse_lock_state(node, "lock", &(entry->hkr.lock));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing hkr lock state for entry %s", entry->name);
        goto err_out;
    }

    result = parse_lock_state(node, "devicelock", &(entry->hkr.device_lock));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing hkr device lock state for entry %s", entry->name);
        goto err_out;
    }

    entry->hkr.present = true;

err_out:
    return result;
}

static int parse_swi_entry(dom_t *dom, struct aha_device *entry)
{
    dom_t *node;
    int result;

    result = 0;
    node = dom_find_node(dom, "switch");
    if(node == NULL){
        goto err_out;
    }

    node = node->child;

    result = parse_switch_state(dom, "state", &(entry->swi.state));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing switch state for entry %s", entry->name);
        goto err_out;

    }

    result = parse_switch_mode(dom, "mode", &(entry->swi.mode));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing switch state for entry %s", entry->name);
        goto err_out;

    }

    result = parse_lock_state(node, "lock", &(entry->swi.lock));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing switch lock state for entry %s", entry->name);
        goto err_out;
    }

    result = parse_lock_state(node, "devicelock", &(entry->swi.device_lock));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing switch device lock state for entry %s", entry->name);
        goto err_out;
    }

    entry->swi.present = true;

err_out:
    return result;
}

static int parse_pwr_entry(dom_t *dom, struct aha_device *entry)
{
    dom_t *node;
    int result;

    result = 0;
    node = dom_find_node(dom, "powermeter");
    if(node == NULL){
        goto err_out;
    }

    node = node->child;

    result = parse_data_ul(node, "power", &(entry->pwr.power));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing power for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(node, "energy", &(entry->pwr.energy));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing energy for entry %s", entry->name);
        goto err_out;
    }

    entry->pwr.present = true;

err_out:
    return result;
}

static int parse_temp_entry(dom_t *dom, struct aha_device *entry)
{
    dom_t *node;
    int result;

    result = 0;
    node = dom_find_node(dom, "temperature");
    if(node == NULL){
        goto err_out;
    }

    node = node->child;

    result = parse_data_long(node, "celsius", &(entry->temp.temp_c));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing temperature for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_long(node, "offset", &(entry->temp.offset));
    if(result != 0){
        ESP_LOGE(TAG, "Error parsing temperature offset for entry %s", entry->name);
        goto err_out;
    }

    entry->temp.present = true;

err_out:
    return result;
}

static struct aha_device *parse_entry(dom_t *dom)
{
    struct aha_device *entry;
    int result;

    result = 0;
    entry = NULL;

    entry = malloc(sizeof(*entry));
    if(entry == NULL){
        ESP_LOGE(TAG, "Out of memory parsing device.");
        result = -ENOMEM;
        goto err_out;
    }

    memset(entry, 0x0, sizeof(*entry));
    INIT_KLIST_HEAD(&(entry->dev_list));
    INIT_KLIST_HEAD(&(entry->grp_list));
    INIT_KLIST_HEAD(&(entry->member_list));

    if(!strcasecmp(dom->name, "device")){
        entry->type = aha_type_device;
    }else if(!strcasecmp(dom->name, "group")){
        entry->type = aha_type_group;
    }else{
        ESP_LOGE(TAG, "Invalid entry type %s", dom->name);
        result = -EINVAL;
        goto err_out;
    }

    result = copy_data_str(dom, "name", entry->name, sizeof(entry->name));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing entry name failed");
        goto err_out;
    }

    result = copy_attr_str(dom, "identifier", entry->identifier, sizeof(entry->identifier));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing identifier failed for entry %s", entry->name);
        goto err_out;
    }

    result = copy_attr_str(dom, "fwversion", entry->fw_version, sizeof(entry->fw_version));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing fwversion failed for entry %s", entry->name);
        goto err_out;
    }

    result = copy_attr_str(dom, "manufacturer", entry->manufacturer, sizeof(entry->manufacturer));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing manufacturer failed for entry %s", entry->name);
        goto err_out;
    }

    result = copy_attr_str(dom, "productname", entry->product_name, sizeof(entry->product_name));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing productname failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_attr_ul(dom, "id", &(entry->id));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing ID failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_attr_ul(dom, "functionbitmask", &(entry->functions));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing functions failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_data_ul(dom->child, "present", &(entry->present));
    if(result != 0){
        ESP_LOGE(TAG, "Parsing present state failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_group_entry(dom->child, entry);
    if(result != 0){
        ESP_LOGE(TAG, "Parsing group info failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_hkr_entry(dom->child, entry);
    if(result != 0){
        ESP_LOGE(TAG, "Parsing hkr info failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_swi_entry(dom->child, entry);
    if(result != 0){
        ESP_LOGE(TAG, "Parsing switch info failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_pwr_entry(dom->child, entry);
    if(result != 0){
        ESP_LOGE(TAG, "Parsing powermeter info failed for entry %s", entry->name);
        goto err_out;
    }

    result = parse_temp_entry(dom->child, entry);
    if(result != 0){
        ESP_LOGE(TAG, "Parsing thermometer info failed for entry %s", entry->name);
        goto err_out;
    }

err_out:
    if(result != 0 && entry != NULL){
        free(entry);
        entry = NULL;
    }

    return entry;
}


static struct aha_data *parse_dom(dom_t *dom)
{
    dom_t *node, *entry;
    struct aha_device *device, *group;
    struct aha_data *data;
    unsigned int idx;
    int result;

    result = 0;

    data = create_data();
    if(data == NULL){
        result = -ENOMEM;
        goto err_out;
    }

    node = dom_find_node(dom, "devicelist");
    if(node == NULL){
        result = -ENOENT;
        goto err_out;
    }

    entry = dom_find_node(node->child, "group");
    while(entry != NULL){
        device = parse_entry(entry);
        if(device != NULL){
            klist_add_tail(&(device->grp_list), &(data->grp_head));
        }
        entry = dom_find_node(entry->next, "group");
    }

    entry = dom_find_node(node->child, "device");
    while(entry != NULL){
        device = parse_entry(entry);
        if(device != NULL){
            klist_add_tail(&(device->dev_list), &(data->dev_head));

            klist_for_each_entry(group, &(data->grp_head), grp_list)
            {
                for(idx = 0;idx < group->grp.member_cnt;++idx){
                    if(device->id == group->grp.members[idx]){
                        device->group = group;
                        klist_add_tail(&(device->member_list),
                                          &(group->member_list));
                        break;
                    }
                }

                if(device->group != NULL){
                    break;
                }
            }
        }

        entry = dom_find_node(entry->next, "device");
    }
    
err_out:
    if(result != 0 && data != NULL){
        aha_data_release(data);
        data = NULL;
    }

    return data;
}

static void dump_hkr(struct aha_hkr *hkr, const char *prefix)
{
    if(hkr->present){
        ESP_LOGI(TAG,
                 "%s[HKR] Set: %lu Act: %lu Comf: %lu Eco: %lu Next: %lu "
                 "Change: %lu: Batt: %lu Lock: %s DevLock: %s Err: %lu",
                 prefix,
                 hkr->set_temp,
                 hkr->act_temp,
                 hkr->comfort_temp,
                 hkr->eco_temp,
                 hkr->next_temp,
                 hkr->next_change,
                 hkr->batt_low,
                 hkr->lock == aha_lock_on ? "on" : "off",
                 hkr->device_lock == aha_lock_on ? "on" : "off",
                 hkr->error);
    }
}

static void dump_swi(struct aha_switch *swi, const char *prefix)
{
    if(swi->present){
        ESP_LOGI(TAG, "%s[SWI] State: %s Mode: %s Lock: %s DevLock: %s",
                 prefix,
                 swi->state == aha_swstate_on ? "on" : "off",
                 swi->mode == aha_switch_auto ? "auto" : "manual",
                 swi->lock == aha_lock_on ? "on" : "off",
                 swi->device_lock == aha_lock_on ? "on" : "off");
    }
}

static void dump_temp(struct aha_thermo *tmp, const char *prefix)
{
    if(tmp->present){
        ESP_LOGI(TAG, "%s[TMP] Temperature: %ld Offset: %ld",
                 prefix,
                 tmp->temp_c,
                 tmp->offset);
    }
}

static void dump_pwr(struct aha_power *pwr, const char *prefix)
{
    if(pwr->present){
        ESP_LOGI(TAG, "%s[PWR] Power: %lu Energy: %lu",
                 prefix,
                 pwr->power,
                 pwr->energy);
    }
}

static void dump_device(struct aha_device *dev, const char *prefix)
{
    ESP_LOGI(TAG, "%s[%s] Name: %s ID: %lu Present: %lu Ident: %s FW: %s "
                  "Manuf: %s ProdName: %s Funcs: 0x%lx",
             prefix,
             dev->type == aha_type_device ? "DEV" : "GRP",
             dev->name,
             dev->id,
             dev->present,
             dev->identifier,
             dev->fw_version,
             dev->manufacturer,
             dev->product_name,
             dev->functions);

    dump_hkr(&(dev->hkr), prefix);
    dump_swi(&(dev->swi), prefix);
    dump_temp(&(dev->temp), prefix);
    dump_pwr(&(dev->pwr), prefix);

}

static void dump_data(struct aha_data *data)
{
    struct aha_device *dev, *grp;

    /* dump groups and its member devices */
    klist_for_each_entry(grp, &(data->grp_head), grp_list){
        dump_device(grp, "");
        klist_for_each_entry(dev, &(grp->member_list), member_list){
            dump_device(dev, " -> ");
        }
    }

    /* dump remaining devices not belonging to a group */
    klist_for_each_entry(dev, &(data->dev_head), dev_list){
        if(dev->group == NULL){
            dump_device(dev, "");
        }
    }
}

static int check_auth(struct auth_data *auth)
{
    char buf[128];
    char *req;
    dom_t *dom, *node;
    int result, written;

    result = 0;
    req = NULL;
    dom = NULL;

    req = malloc(HTTP_REQ_SIZE);
    if(req == NULL){
        ESP_LOGE(TAG, "Out of memory for request");
        result = -ENOMEM;
        goto err_out;
    }
    memset(req, 0x0, HTTP_REQ_SIZE);

    written = snprintf(buf, sizeof(buf), SID_CHECK, auth->sid);
    if(written >= sizeof(buf)){
        ESP_LOGE(TAG, "SID check too big");
        result = -EINVAL;
        goto err_out;
    }

    written = snprintf(req, HTTP_REQ_SIZE, HTTP_REQ, buf, aha_cfg.fbox_port);
    if(written >= HTTP_REQ_SIZE){
        ESP_LOGE(TAG, "HTTP SID check too big");
        result = -EINVAL;
        goto err_out;
    }

    result = do_http_req(aha_cfg.fbox_addr, aha_cfg.fbox_port, &dom, req);
    if(result != 0){
        ESP_LOGE(TAG, "HTTP SID check failed");
        goto err_out;
    }

    node = dom_find_node(dom, "SID");
    if(node && strncmp(node->data, "0000000000000000", 16)){
        ESP_LOGI(TAG, "SID %s still valid", auth->sid);
        goto err_out;
    }

    result = copy_data_str(dom, "Challenge", auth->nonce, sizeof(auth->nonce));
    if(result != 0){
        goto err_out;
    }

    result = gen_sid_auth(auth);
    if(result != 0){
        ESP_LOGE(TAG, "Generating auth response failed.");
        goto err_out;
    }

    dom_free(dom);
    dom = NULL;

    memset(req, 0x0, HTTP_REQ_SIZE);
    written = snprintf(buf, sizeof(buf), SID_GET, auth->user, auth->nonce,
            auth->auth);
    if(written >= sizeof(buf)){
        ESP_LOGE(TAG, "SID request too big");
        result = -EINVAL;
        goto err_out;
    }

    written = snprintf(req, HTTP_REQ_SIZE, HTTP_REQ, buf, aha_cfg.fbox_addr);
    if(written >= HTTP_REQ_SIZE){
        ESP_LOGE(TAG, "HTTP SID request too big");
        result = -EINVAL;
        goto err_out;
    }

    result = do_http_req(aha_cfg.fbox_addr, aha_cfg.fbox_port, &dom, req);
    if(result != 0){
        ESP_LOGE(TAG, "HTTP SID request failed");
        goto err_out;
    }

    result = copy_data_str(dom, "SID", auth->sid, sizeof(auth->sid));
    if(result != 0 || !strcmp(auth->sid, "0000000000000000")){
        ESP_LOGE(TAG, "Unable to retrieve valid SID");
        result = -EPERM;
        goto err_out;
    }

    ESP_LOGI(TAG, "New SID: %s", auth->sid);

err_out:
    if(req != NULL){
        free(req);
    }

    if(dom != NULL){
        dom_free(dom);
    }

    return result;
}

static dom_t *fetch_data(struct auth_data *auth)
{
    char buf[128];
    char *req;
    dom_t *dom;
    int result, written;

    result = 0;
    req = NULL;
    dom = NULL;

    req = malloc(HTTP_REQ_SIZE);
    if(req == NULL){
        ESP_LOGE(TAG, "Out of memory for request");
        result = -ENOMEM;
        goto err_out;
    }
    memset(req, 0x0, HTTP_REQ_SIZE);

    written = snprintf(buf, sizeof(buf), HKR_REQ, auth->sid);
    if(written >= sizeof(buf)){
        ESP_LOGE(TAG, "HKR request too big");
        result = -EINVAL;
        goto err_out;
    }

    written = snprintf(req, HTTP_REQ_SIZE, HTTP_REQ, buf, aha_cfg.fbox_addr);
    if(written >= HTTP_REQ_SIZE){
        ESP_LOGE(TAG, "HTTP HKR request too big");
        result = -EINVAL;
        goto err_out;
    }

    result = do_http_req(aha_cfg.fbox_addr, aha_cfg.fbox_port, &dom, req);
    if(result != 0){
        ESP_LOGE(TAG, "HTTP HKR check failed");
        goto err_out;
    }

err_out:
    if(result != 0 && dom != NULL){
        dom_free(dom);
        dom = NULL;
    }

    if(req != NULL){
        free(req);
    }

    return dom;
}

static enum aha_heat_mode dev_need_heat(struct aha_device *dev)
{
    enum aha_heat_mode result;
    struct aha_hkr *hkr;
    time_t now;

    hkr = &(dev->hkr);

    /* default to off*/
    result = aha_heat_off;

    /* ignore if this is not a hkr */
    if(hkr->present == false){
        goto err_out;
    }

    if(hkr->set_temp == HEAT_FORCE_ON){
        result = aha_heat_on;
        goto err_out;
    }

    if(hkr->set_temp == HEAT_FORCE_OFF){
        result = aha_heat_off;
        goto err_out;
    }

    /* do not change heat mode if the target temparature will be set lower than
     * the current actual temperature within the hysteresis time span        */
    time(&now);
    if((hkr->act_temp >= hkr->next_temp)
        && ((hkr->next_change - now) <= CONFIG_HYSTERESIS))
    {
        result = aha_heat_keep;
        goto err_out;
    }

    /* no imminent target temperature change ahead, just compare actual and
     * target temperature           */
    if(hkr->act_temp < hkr->set_temp){
        result = aha_heat_on;
    }

err_out:
    return result;
}

static enum aha_heat_mode need_heat(struct aha_data *data)
{
    struct aha_device *device;
    enum aha_heat_mode result, tmp;

    result = aha_heat_off;

    if(data == NULL){
        goto err_out;
    }

    klist_for_each_entry(device, &(data->dev_head), dev_list){
        tmp = dev_need_heat(device);
        if(tmp >= aha_heat_on){
            ESP_LOGI(TAG,"%s", device->name);
            result = tmp;
        }
    }

err_out:
    return result;
}

static void fire(int on_off)
{
    ESP_LOGI(TAG, "Fire %s!", on_off == 0 ? "off" : "on");
    gpio_set_level(GPIO_HEAT, on_off == 0 ? 0 : 1);
}

static int gpio_setup(void)
{
    int result = 0;
    gpio_config_t io_conf;

    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = (uint64_t)((1ULL << GPIO_HEAT)
                                    | (1ULL << GPIO_LED));
    io_conf.pull_down_en = 0;
    io_conf.pull_up_en = 0;
    gpio_config(&io_conf);

    return result;
}

static void timer_cb(TimerHandle_t timer)
{
    xEventGroupSetBits(aha_event_group, BIT_TIMER);
}

esp_err_t aha_set_cfg(struct aha_cfg *cfg, bool reload)
{
    esp_err_t result;
    nvs_handle handle;

    if(aha_cfg_lock == NULL){

        return ESP_ERR_TIMEOUT;
    }

    result = nvs_open(AHA_NVS_NAMESPC, NVS_READWRITE, &handle);
    if(result != ESP_OK){
        return result;
    }

    if(xSemaphoreTake(aha_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }

    result = nvs_set_str(handle, "fbox_user", cfg->fbox_user);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_set_str(handle, "fbox_pass", cfg->fbox_pass);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_set_str(handle, "fbox_addr", cfg->fbox_addr);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_set_str(handle, "fbox_port", cfg->fbox_port);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_commit(handle);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    if(reload){
        xEventGroupSetBits(aha_event_group, BIT_RELOAD);
    }

err_out_unlock:
    xSemaphoreGive(aha_cfg_lock);

err_out:
    nvs_close(handle);

    return result;
}

esp_err_t aha_get_cfg(struct aha_cfg *cfg)
{
    esp_err_t result;
    size_t len;
    nvs_handle handle;

    if(aha_cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    result = nvs_open(AHA_NVS_NAMESPC, NVS_READONLY, &handle);
    if(result != ESP_OK){
        return result;
    }

    if(xSemaphoreTake(aha_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }
    
    memset(cfg, 0x0, sizeof(*cfg));

    len = sizeof(cfg->fbox_user);
    result = nvs_get_str(handle, "fbox_user", cfg->fbox_user, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    len = sizeof(cfg->fbox_pass);
    result = nvs_get_str(handle, "fbox_pass", cfg->fbox_pass, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    len = sizeof(cfg->fbox_addr);
    result = nvs_get_str(handle, "fbox_addr", cfg->fbox_addr, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    len = sizeof(cfg->fbox_port);
    result = nvs_get_str(handle, "fbox_port", cfg->fbox_port, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

err_out_unlock:
    xSemaphoreGive(aha_cfg_lock);

err_out:
    nvs_close(handle);

    return result;
}

struct aha_data *aha_data_get(void)
{
    struct aha_data *data;

    data = NULL;
    if(aha_data_lock == NULL || curr_aha_data == NULL){
        goto err_out;
    }

    if(xSemaphoreTake(aha_data_lock, 100 * portTICK_PERIOD_MS) == pdTRUE){
        kref_get(&(curr_aha_data->ref_cnt));
        data = curr_aha_data;
        xSemaphoreGive(aha_data_lock);
    }

err_out:
    return data;
}

void aha_data_release(struct aha_data *data)
{
    if(data != NULL){
        kref_put(&(data->ref_cnt), release_data);
    }
}

void aha_task_suspend(void)
{
    xEventGroupSetBits(aha_event_group, BIT_SUSPEND);
}

void aha_task_resume(void)
{
    xEventGroupClearBits(aha_event_group, BIT_SUSPEND);
}

void avm_aha_task(void *pvParameters)
{
    int result;
    struct auth_data auth_data;
    struct aha_data *old_data, *new_data;
    enum aha_heat_mode heat_mode;
    tcpip_adapter_ip_info_t info;
    wifi_ap_record_t wapr;
    dom_t *dom;
    EventBits_t events;

    aha_data_lock = xSemaphoreCreateMutex();
    if(aha_data_lock == NULL){
        ESP_LOGE(TAG, "Creating aha_data_lock failed.");
        goto err_out;
    }

    aha_cfg_lock = xSemaphoreCreateMutex();
    if(aha_cfg_lock == NULL){
        ESP_LOGE(TAG, "Creating aha_cfg_lock failed.");
        goto err_out;
    }

    aha_event_group = xEventGroupCreate();
    if(aha_event_group == NULL){
        ESP_LOGE(TAG, "Creating aha_event_group failed.");
        goto err_out;
    }

    /* Force main loop to wait until released from main task.
     * Also trigger loading of config from NVS.                       */
    xEventGroupSetBits(aha_event_group, (BIT_SUSPEND | BIT_RELOAD));

    aha_timer = xTimerCreate("AHA_Timer", pdMS_TO_TICKS(10000), pdTRUE, NULL, timer_cb);
    if(aha_timer == NULL){
        ESP_LOGE(TAG, "Creating aha_timer failed.");
        goto err_out;
    }

    result = xTimerStart(aha_timer, portMAX_DELAY);
    if(result == pdFAIL){
        ESP_LOGE(TAG, "Starting aha_timer failed.");
        goto err_out;
    }

    result = gpio_setup();
    if(result != 0){
        ESP_LOGE(TAG, "GPIO setup failed.");
        goto err_out;
    }

    result = esp_task_wdt_init(TWDT_TIMEOUT_S, true);
    if(result != 0){
        ESP_LOGE(TAG, "WDT setup failed.");
        goto err_out;
    }

    result = esp_task_wdt_add(NULL);
    if(result != 0){
        ESP_LOGE(TAG, "WDT task add failed.");
        goto err_out;
    }

    result = esp_task_wdt_status(NULL);
    if(result != 0){
        ESP_LOGE(TAG, "WDT status check failed.");
        goto err_out;
    }

    do{
        /* Wait for and clear timer bit */
        events = xEventGroupWaitBits(aha_event_group, BIT_TIMER,
                                     true, false, portMAX_DELAY);

        if(events & BIT_SUSPEND){
            ESP_LOGI(TAG, "Task suspended");
            goto wait_retry;
        }

        if(events & BIT_RELOAD){
            result = aha_get_cfg(&aha_cfg);
            if(result == ESP_OK){
            ESP_LOGI(TAG, "Config reloaded");
                xEventGroupClearBits(aha_event_group, BIT_RELOAD);

                memset(&auth_data, 0x0, sizeof(auth_data));
                strlcpy(auth_data.user, aha_cfg.fbox_user, sizeof(auth_data.user));
                strlcpy(auth_data.pass, aha_cfg.fbox_pass, sizeof(auth_data.pass));
            } else {
                ESP_LOGI(TAG, "Config reload failed");
                goto wait_retry;
            }
        }

        result = esp_wifi_sta_get_ap_info(&wapr);
        if(result != ESP_OK){
            goto wait_retry;
        }

        result = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &info);
        if(result != ESP_OK || info.ip.addr == IPADDR_ANY){
            goto wait_retry;
        }

        gpio_set_level(GPIO_LED, 1);
        
        result = check_auth(&auth_data);
        if(result != 0){
            goto wait_retry;
        }

        dom = fetch_data(&auth_data);
        if(dom == NULL){
            ESP_LOGI(TAG, "Fetching data failed");
            goto wait_retry;
        }

        new_data = parse_dom(dom);
        dom_free(dom);
        if(new_data == NULL){
            ESP_LOGE(TAG, "Parsing data failed");
            goto wait_retry;
        }

        dump_data(new_data);

        heat_mode = need_heat(new_data);
        switch(heat_mode){
        case aha_heat_on:
            fire(1);
            break;
        case aha_heat_off:
            fire(0);
            break;
        default:
            // do nothing
            break;
        }

        gpio_set_level(GPIO_LED, 0);

        ESP_LOGI(TAG, "Free heap before: 0x%x", esp_get_free_heap_size());
        /* try to replace public aha state data */
        if(xSemaphoreTake(aha_data_lock, 100 * portTICK_PERIOD_MS) == pdTRUE){
            old_data = curr_aha_data;
            curr_aha_data = new_data;
            if(old_data != NULL){
                aha_data_release(old_data);
            }
            xSemaphoreGive(aha_data_lock);
        } else {
            ESP_LOGI(TAG, "Unable to get aha_data_lock for update.");
            aha_data_release(new_data);
        }
        ESP_LOGI(TAG, "Free heap after: 0x%x", esp_get_free_heap_size());

wait_retry:
        result = esp_task_wdt_reset();
        if(result != 0){
            ESP_LOGE(TAG, "WDT reset failed.");
            goto err_out;
        }
    }while(1);

err_out:
    while(1)
        ;

    return;
}
