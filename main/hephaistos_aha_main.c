/*
 * main.c
 *
 *  Created on: 04.11.2017
 *      Author: tido
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
#include <list.h>
#if !defined(ESP_PLATFORM)
#include <bsd/bsd.h>
#endif

#include <sdkconfig.h>

#if defined(ESP_PLATFORM)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
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

#include "apps/sntp/sntp.h"
#endif // defined(ESP_PLATFORM)

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#if defined(ESP_PLATFORM)
#include "mbedtls/esp_debug.h"
#endif // defined(ESP_PLATFORM)
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/md5.h"

/* The examples use simple WiFi configuration that you can set via
 'make menuconfig'.

 If you'd rather not, just change the below entries to strings with
 the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
 */
#define WIFI_SSID       CONFIG_WIFI_SSID
#define WIFI_PASS       CONFIG_WIFI_PASSWORD
#define FBOX_USER       CONFIG_FBOX_USER
#define FBOX_PASS       CONFIG_FBOX_PASSWORD
#define FBOX_ADDR       CONFIG_FBOX_ADDR
#define FBOX_PORT       CONFIG_FBOX_PORT
#define TIMEZONE        CONFIG_TIMEZONE
#define GPIO_HEAT       CONFIG_GPIO_HEAT
#define GPIO_LED        CONFIG_GPIO_LED

#define TWDT_TIMEOUT_S          300
#define TASK_RESET_PERIOD_S     5

#if defined(ESP_PLATFORM)
/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
 * but we only care about one event - are we connected
 * to the AP with an IP? */
const int CONNECTED_BIT = BIT0;
#else
#define ESP_LOGE(tag, format, ... )  printf("[%s]" format "\n", tag, ##__VA_ARGS__)
#define ESP_LOGI(tag, format, ... )  printf("[%s]" format "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, format, ... )  printf("[%s]" format "\n", tag, ##__VA_ARGS__)
#define ESP_LOGD(tag, format, ... )  printf("[%s]" format "\n", tag, ##__VA_ARGS__)
#endif // defined(ESP_PLATFORM)

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))
static void debug_led(unsigned int led, int on_off);

static const char *TAG = "hephaistos";

static const char *HTTP_REQ = 
        "GET %s HTTP/1.0\r\n"
        "HOST: 192.168.178.1\r\n"
        "CONNECTION: keep-alive\r\n"
        "USER-AGENT: AVM UPnP/1.0 Client 1.0\r\n"
        "\r\n";

static const char *SID_CHECK = "/login_sid.lua?sid=%s";
static const char *SID_GET = "/login_sid.lua?username=%s&response=%s-%s";
static const char *HKR_REQ = "/webservices/homeautoswitch.lua?switchcmd=getdevicelistinfos&sid=%s";

#define HTTP_REQ_SIZE   1024

enum aha_heat_mode {
    aha_heat_off = 0,
    aha_heat_keep,
    aha_heat_on
};

struct aha_state
{
#if defined(ESP_PLATFORM)
    SemaphoreHandle_t sema;
    TimerHandle_t hyst_timer;
#endif
    struct aha_list_head dev_head; // list of all devices
    struct aha_list_head grp_head; // list of all groups
};

static struct aha_state state;

#define MAX_ENTRY_LEN       128
#define MAX_GROUP_MEMBERS   16

#define HEAT_FORCE_ON   0xFE
#define HEAT_FORCE_OFF  0xFD

enum aha_entry_type
{
    aha_type_invalid = 0,
    aha_type_device,
    aha_type_group,
};

enum aha_lock_mode
{
    aha_lock_unknown = 0,
    aha_lock_on,
    aha_lock_off,
};

enum aha_switch_mode
{
    aha_switch_unknown = 0,
    aha_switch_auto,
    aha_switch_manual,
};

enum aha_switch_state
{
    aha_swstate_unknown = 0,
    aha_swstate_on,
    aha_swstate_off,
};

enum aha_alarm_mode
{
    aha_alarm_unknown = 0,
    aha_alarm_off,
    aha_alarm_on,
};

struct aha_hkr
{
    bool present;
    unsigned long set_temp;
    unsigned long act_temp;
    unsigned long comfort_temp;
    unsigned long eco_temp;
    unsigned long next_temp;
    unsigned long next_change;
    unsigned long batt_low;
    enum aha_lock_mode lock;
    enum aha_lock_mode device_lock;
    unsigned long error;
};

struct aha_switch
{
    bool present;
    enum aha_switch_state state;
    enum aha_switch_mode mode;
    enum aha_lock_mode lock;
    enum aha_lock_mode device_lock;
};

struct aha_power
{
    bool present;
    unsigned long power;
    unsigned long energy;
};

struct aha_thermo
{
    bool present;
    long temp_c;
    long offset;
};

struct aha_alarm
{
    bool present;
    enum aha_alarm_mode mode;
};

struct aha_group
{
    bool present;
    unsigned long master_dev;
    unsigned long members[MAX_GROUP_MEMBERS];
    unsigned int member_cnt;
};

struct aha_device
{
    struct aha_list_head dev_list;
    struct aha_list_head grp_list;
    struct aha_list_head member_list;
    enum aha_entry_type type;
    char name[MAX_ENTRY_LEN];
    char identifier[MAX_ENTRY_LEN];
    char fw_version[MAX_ENTRY_LEN];
    char manufacturer[MAX_ENTRY_LEN];
    char product_name[MAX_ENTRY_LEN];
    unsigned long functions;
    unsigned long id;
    unsigned long present;
    struct aha_device *group;
    struct aha_group grp;
    struct aha_switch swi;
    struct aha_power pwr;
    struct aha_thermo temp;
    struct aha_alarm alarm;
    struct aha_hkr hkr;
};

static int initialise_state(void)
{
    int result;

    result = 0;
    memset(&state, 0x0, sizeof(state));

    AHA_INIT_LIST_HEAD(&state.dev_head);
    AHA_INIT_LIST_HEAD(&state.grp_head);

#if defined(ESP_PLATFORM)
    state.sema = xSemaphoreCreateBinary();
    if(state.sema == NULL){
        ESP_LOGE(TAG, "Creating semaphore failed");
        result = -ENOMEM;
    }
#endif

    return result;
}

#if defined(ESP_PLATFORM)
static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
         * auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initialise_wifi(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password =  WIFI_PASS,
        },
    };

    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}
#endif // defined(ESP_PLATFORM)

struct auth_data
{
    char user[128];
    char pass[128];
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
    char buf[MAX_ENTRY_LEN];
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
    AHA_INIT_LIST_HEAD(&(entry->dev_list));
    AHA_INIT_LIST_HEAD(&(entry->grp_list));
    AHA_INIT_LIST_HEAD(&(entry->member_list));

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

static void free_devices(void)
{
    struct aha_device *device, *group, *tmp_dev, *tmp_grp;

    aha_list_for_each_entry_safe(group, tmp_grp, &(state.grp_head), grp_list)
    {
        /* remove all devices from the group's member list */
        aha_list_for_each_entry_safe(device, tmp_dev, &(group->member_list), member_list)
        {
            aha_list_del(&(device->member_list));
            device->group = NULL;
        }

        /* remove group from group list */
        aha_list_del_init(&(group->grp_list));

        free(group);
    }

    aha_list_for_each_entry_safe(device, tmp_dev, &(state.dev_head), dev_list)
    {
        /* remove device from device list */
        aha_list_del(&(device->dev_list));
        free(device);
    }
}

static int parse_dom(dom_t *dom)
{
    dom_t *node, *entry;
    struct aha_device *device, *group;
    unsigned int idx;
    int result;

    free_devices();

    result = 0;
    node = dom_find_node(dom, "devicelist");
    if(node == NULL){
        result = -ENOENT;
        goto err_out;
    }

    entry = dom_find_node(node->child, "group");
    while(entry != NULL){
        device = parse_entry(entry);
        if(device != NULL){
            aha_list_add_tail(&(device->grp_list), &(state.grp_head));
        }
        entry = dom_find_node(entry->next, "group");
    }

    entry = dom_find_node(node->child, "device");
    while(entry != NULL){
        device = parse_entry(entry);
        if(device != NULL){
            aha_list_add_tail(&(device->dev_list), &(state.dev_head));

            aha_list_for_each_entry(group, &(state.grp_head), grp_list)
            {
                for(idx = 0;idx < group->grp.member_cnt;++idx){
                    if(device->id == group->grp.members[idx]){
                        device->group = group;
                        aha_list_add_tail(&(device->member_list),
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
    return result;
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

static void dump_state(void)
{
    struct aha_device *dev, *grp;

    /* dump groups and its member devices */
    aha_list_for_each_entry(grp, &(state.grp_head), grp_list){
        dump_device(grp, "");
        aha_list_for_each_entry(dev, &(grp->member_list), member_list){
            dump_device(dev, " -> ");
        }
    }

    /* dump remaining devices not belonging to a group */
    aha_list_for_each_entry(dev, &(state.dev_head), dev_list){
        if(dev->group == NULL){
            dump_device(dev, "");
        }
    }
}

#if !defined(TESTDATA_FILE)
static int check_auth(struct auth_data *data)
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

    written = snprintf(buf, sizeof(buf), SID_CHECK, data->sid);
    if(written >= sizeof(buf)){
        ESP_LOGE(TAG, "SID check too big");
        result = -EINVAL;
        goto err_out;
    }

    written = snprintf(req, HTTP_REQ_SIZE, HTTP_REQ, buf);
    if(written >= HTTP_REQ_SIZE){
        ESP_LOGE(TAG, "HTTP SID check too big");
        result = -EINVAL;
        goto err_out;
    }

    result = do_http_req(FBOX_ADDR, FBOX_PORT, &dom, req);
    if(result != 0){
        ESP_LOGE(TAG, "HTTP SID check failed");
        goto err_out;
    }

    node = dom_find_node(dom, "SID");
    if(node && strncmp(node->data, "0000000000000000", 16)){
        ESP_LOGI(TAG, "SID %s still valid", data->sid);
        goto err_out;
    }

    result = copy_data_str(dom, "Challenge", data->nonce, sizeof(data->nonce));
    if(result != 0){
        goto err_out;
    }

    result = gen_sid_auth(data);
    if(result != 0){
        ESP_LOGE(TAG, "Generating auth response failed.");
        goto err_out;
    }

    dom_free(dom);
    dom = NULL;

    memset(req, 0x0, HTTP_REQ_SIZE);
    written = snprintf(buf, sizeof(buf), SID_GET, FBOX_USER, data->nonce,
            data->auth);
    if(written >= sizeof(buf)){
        ESP_LOGE(TAG, "SID request too big");
        result = -EINVAL;
        goto err_out;
    }

    written = snprintf(req, HTTP_REQ_SIZE, HTTP_REQ, buf);
    if(written >= HTTP_REQ_SIZE){
        ESP_LOGE(TAG, "HTTP SID request too big");
        result = -EINVAL;
        goto err_out;
    }

    result = do_http_req(FBOX_ADDR, FBOX_PORT, &dom, req);
    if(result != 0){
        ESP_LOGE(TAG, "HTTP SID request failed");
        goto err_out;
    }

    result = copy_data_str(dom, "SID", data->sid, sizeof(data->sid));
    if(result != 0 || !strcmp(data->sid, "0000000000000000")){
        ESP_LOGE(TAG, "Unable to retrieve valid SID");
        result = -EPERM;
        goto err_out;
    }

    ESP_LOGI(TAG, "New SID: %s", data->sid);

err_out:
    if(req != NULL){
        free(req);
    }

    if(dom != NULL){
        dom_free(dom);
    }

    return result;
}

static dom_t *fetch_data(struct auth_data *data)
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

    written = snprintf(buf, sizeof(buf), HKR_REQ, data->sid);
    if(written >= sizeof(buf)){
        ESP_LOGE(TAG, "HKR request too big");
        result = -EINVAL;
        goto err_out;
    }

    written = snprintf(req, HTTP_REQ_SIZE, HTTP_REQ, buf);
    if(written >= HTTP_REQ_SIZE){
        ESP_LOGE(TAG, "HTTP HKR request too big");
        result = -EINVAL;
        goto err_out;
    }

    result = do_http_req(FBOX_ADDR, FBOX_PORT, &dom, req);
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
#else
static int check_auth(struct auth_data *data)
{
    return 0;
}

static dom_t *fetch_data(struct auth_data *data)
{
    dom_t *dom;

    dom = NULL;
    errno = 0;
    dom = dom_parse_file_name(TESTDATA_FILE);
    if(dom == NULL){
        ESP_LOGE(TAG, "Parsing test data file %s failed: %s", TESTDATA_FILE, strerror(errno));
        goto err_out;
    }

err_out:
    return dom;
}
#endif

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

static enum aha_heat_mode need_heat(void)
{
    struct aha_device *device;
    enum aha_heat_mode result, tmp;

    result = aha_heat_off;
    aha_list_for_each_entry(device, &(state.dev_head), dev_list){
        tmp = dev_need_heat(device);
        if(tmp >= aha_heat_on){
            ESP_LOGI(TAG,"%s", device->name);
            result = tmp;
        }
    }

    return result;
}

static void fire(int on_off)
{
    ESP_LOGI(TAG, "Fire %s!", on_off == 0 ? "off" : "on");
#if defined(ESP_PLATFORM)
    gpio_set_level(GPIO_HEAT, on_off == 0 ? 0 : 1);
#endif
}

static int gpio_setup(void)
{
    int result = 0;
#if defined(ESP_PLATFORM)
    gpio_config_t io_conf;

    io_conf.intr_type = GPIO_PIN_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = (uint64_t)((1ULL << GPIO_HEAT)
                                    | (1ULL << GPIO_LED));
    io_conf.pull_down_en = 0;
    io_conf.pull_up_en = 0;
    gpio_config(&io_conf);
#endif

    return result;
}

static void hephaistos_task(void *pvParameters)
{
    int result;
    struct auth_data auth_data;
    enum aha_heat_mode heat_mode;
    dom_t *dom;

    memset(&auth_data, 0x0, sizeof(auth_data));
    strcpy(auth_data.user, FBOX_USER);
    strcpy(auth_data.pass, FBOX_PASS);

    result = gpio_setup();
    if(result != 0){
        ESP_LOGE(TAG, "GPIO setup failed.");
        goto err_out;
    }

#if defined(ESP_PLATFORM)
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

    result = esp_task_wdt_reset();
    if(result != 0){
        ESP_LOGE(TAG, "WDT reset failed.");
        goto err_out;
    }
#endif

    do{
#if defined(ESP_PLATFORM)
        gpio_set_level(GPIO_LED, 1);

        /* Wait for the callback to set the CONNECTED_BIT in the
         * event group.       */
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                            false, true, portMAX_DELAY);
#endif
        result = check_auth(&auth_data);
        if(result != 0){
            goto wait_retry;
        }

        dom = fetch_data(&auth_data);
        if(dom == NULL){
            ESP_LOGI(TAG, "Fetching data failed");
            goto wait_retry;
        }

        result = parse_dom(dom);
        dom_free(dom);
        if(result != 0){
            ESP_LOGE(TAG, "Parsing data failed");
            goto wait_retry;
        }

        dump_state();

        heat_mode = need_heat();
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

#if defined(ESP_PLATFORM)
        gpio_set_level(GPIO_LED, 0);

        result = esp_task_wdt_reset();
        if(result != 0){
            ESP_LOGE(TAG, "WDT reset failed.");
            goto err_out;
        }
#endif

wait_retry:
        sleep(10);
    }while(1);

err_out:
    while(1)
        ;

    return;
}
#if defined(ESP_PLATFORM)
static void initialise_sntp(void)
{
    ESP_LOGI(TAG, "Initialising SNTP");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
}

static void obtain_time(void)
{
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                        false, true, portMAX_DELAY);
    initialise_sntp();

    // wait for time to be set
    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 10;
    while(timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
        ESP_LOGE(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
        time(&now);
        localtime_r(&now, &timeinfo);
    }
}

#endif
void get_time(void)
{
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];

#if defined(ESP_PLATFORM)
    time(&now);
    localtime_r(&now, &timeinfo);

    // Is time set? If not, tm_year will be (1970 - 1900).
    if (timeinfo.tm_year < (2016 - 1900)) {
        ESP_LOGI(TAG, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
        obtain_time();
    }
#endif

    // Set timezone to Eastern Standard Time and print local time
    setenv("TZ", TIMEZONE, 1);
    tzset();
    // update 'now' variable with current time
    time(&now);
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time is: %s", strftime_buf);

}

#if defined(ESP_PLATFORM)
void app_main()
{
    ESP_ERROR_CHECK(nvs_flash_init());
    initialise_wifi();
    //get_time();
    initialise_state();
    xTaskCreate(&hephaistos_task, "hephaistos_task", 8192, NULL, 5, NULL);
}
#else
int main(int argc, char **argv)
{
    get_time();
    initialise_state();
    hephaistos_task(NULL);
    return 0;
}
#endif
