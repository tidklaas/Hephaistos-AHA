/*
 * This file is part of the Hephaistos-AHA project.
 * Copyright (C) 2018-2019 Tido Klaassen <tido_hephaistos@4gh.eu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#include <stdarg.h>
#include <time.h>
#include <esp_wifi_types.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <libesphttpd/esp.h>
#include <heph_cgi.h>
#include <hephaistos.h>
#include <avm_aha.h>
#include <http_srv.h>
#include <wifi_manager.h>
#include <cJSON.h>
#include <sys/param.h>

static const char *TAG = "CGI";

struct aha_dump
{
    char *str;
    size_t offset;
};

CgiStatus cgi_redirect(HttpdConnData *conn)
{
    struct http_srv_cfg http_cfg;
    struct aha_cfg aha_cfg;
    esp_err_t result;

    if(conn->isConnectionClosed){
        /* Connection aborted. Clean up. */
        return HTTPD_CGI_DONE;
    }

    /*
     * Check if NVS contains valid configurations for HTTP user, Wifi
     * and AHA. Force user to enter data if none is found.
     */

    /* HTTP user config */
    result = http_get_cfg(&http_cfg, cfg_nvs);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/user/");
        goto on_exit;
    }

    /* WiFi config */
    if(!esp_wmngr_nvs_valid()){
        httpdRedirect(conn, "/wifi/");
        goto on_exit;
    }

    /* AHA config */
    result = aha_get_cfg(&aha_cfg, cfg_nvs);
    if(result != ESP_OK){
        /* FIXME: handle temporary error */
        httpdRedirect(conn, "/aha/ahacfg.tpl");
        goto on_exit;
    }

    httpdRedirect(conn, "/index.tpl");

on_exit:
    return HTTPD_CGI_DONE;
}

int tpl_main(HttpdConnData *conn, char *token, void **arg)
{
    struct aha_data *data;
    time_t now;
    struct tm tm;
    div_t uptime;
    unsigned int days, hours, min, sec;
    char reply[64];

    if(conn->isConnectionClosed || token == NULL){
        return HTTPD_CGI_DONE;
    }

    memset(reply, 0x0, sizeof(reply));

    if(strcmp(token, "heater") == 0){
        data = aha_data_get();
        if(data == NULL){
            strlcpy(reply, "UNKNOWN", sizeof(reply));
        }else{
            strlcpy(reply, data->heat_on ? "ON" : "OFF", sizeof(reply));
            aha_data_release(data);
        }
    } else if(strcmp(token, "systime") == 0){
        now = time(NULL);
        memset(&tm, 0x0, sizeof(tm));
        localtime_r(&now, &tm);
        asctime_r(&tm, reply);
    } else if(strcmp(token, "uptime") == 0){
        uptime.quot = esp_timer_get_time() / 1000000; /* time in microsecs */
        uptime = div(uptime.quot, 60);
        sec = uptime.rem;
        uptime = div(uptime.quot, 60);
        min = uptime.rem;
        uptime = div(uptime.quot, 24);
        hours = uptime.rem;
        days = uptime.quot;
        sprintf(reply, "%dd %02dh %02dm %02ds", days, hours, min, sec);
    } else if(strcmp(token, "heap") == 0){
        sprintf(reply, "%d", esp_get_free_heap_size());
    } else if(strcmp(token, "ahamsg") == 0){
        data = aha_data_get();
        if(data == NULL){
            strlcpy(reply, "NONE", sizeof(reply));
        }else{
            strlcpy(reply, data->msg, sizeof(reply));
            aha_data_release(data);
        }
    }

    httpdSend(conn, reply, -1);
    return HTTPD_CGI_DONE;
}

int tpl_user(HttpdConnData *conn, char *token, void **arg)
{
    struct http_srv_cfg http_cfg;
    esp_err_t result;
    char buff[128];

    if(conn->isConnectionClosed || token == NULL){
        return HTTPD_CGI_DONE;
    }

    strlcpy(buff, "<INVALID>", sizeof(buff));

    result = http_get_cfg(&http_cfg, cfg_ram);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Fetching current user config failed.", __func__);
        goto on_exit;
    }

    if(strcmp(token, "user") == 0){
        strlcpy(buff, http_cfg.user, sizeof(buff));
    }else if(strcmp(token, "pass") == 0){
        strlcpy(buff, http_cfg.pass, sizeof(buff));
    }

on_exit:
    httpdSend(conn, buff, -1);
    return HTTPD_CGI_DONE;
}

CgiStatus cgi_user_set(HttpdConnData *conn)
{
    struct http_srv_cfg cfg;
    esp_err_t result;

    if(conn->isConnectionClosed){
        return HTTPD_CGI_DONE;
    }

    memset(&cfg, 0x0, sizeof(cfg));

    httpdFindArg(conn->post.buff, "user", cfg.user, sizeof(cfg.user));
    httpdFindArg(conn->post.buff, "pass", cfg.pass, sizeof(cfg.pass));

    if(strlen(cfg.user) > 0 && strlen(cfg.pass) > 0){
        result = http_set_cfg(&cfg, true);
        if(result == ESP_OK){
            httpdRedirect(conn, "/");
            goto on_exit;
        }
    }

    httpdRedirect(conn, "/user");

on_exit:
    return HTTPD_CGI_DONE;
}

CgiStatus cgi_wifi_reset(HttpdConnData *conn)
{
    if(conn->isConnectionClosed){
        return HTTPD_CGI_DONE;
    }

    httpdRedirect(conn, "/wifi/working.html");

    esp_wmngr_stop();
    esp_wmngr_reset_cfg();
    esp_wmngr_start();

    return HTTPD_CGI_DONE;
}

int tpl_ahacfg(HttpdConnData *conn, char *token, void **arg)
{
    char buff[128];
    struct aha_cfg cfg;
    esp_err_t result;

    if(conn->isConnectionClosed || token == NULL){
        return HTTPD_CGI_DONE;
    }

    strlcpy(buff, "<INVALID>", sizeof(buff));

    /* Get currently active AHA configuration */
    result = aha_get_cfg(&cfg, cfg_ram);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Fetching current AHA config failed.", __func__);
        goto on_exit;
    }

    if(strcmp(token, "fbox_user") == 0){
        strlcpy(buff, cfg.fbox_user, sizeof(buff));
    }else if(strcmp(token, "fbox_pass") == 0){
        strlcpy(buff, cfg.fbox_pass, sizeof(buff));
    }else if(strcmp(token, "fbox_addr") == 0){
        strlcpy(buff, cfg.fbox_addr, sizeof(buff));
    }else if(strcmp(token, "fbox_port") == 0){
        strlcpy(buff, cfg.fbox_port, sizeof(buff));
    }

on_exit:
    httpdSend(conn, buff, -1);
    return HTTPD_CGI_DONE;
}

CgiStatus cgi_aha_setcfg(HttpdConnData *conn)
{
    struct aha_cfg cfg;
    esp_err_t result;

    if(conn->isConnectionClosed){
        return HTTPD_CGI_DONE;
    }

    memset(&cfg, 0x0, sizeof(cfg));

    httpdFindArg(conn->post.buff, "fbox_user", cfg.fbox_user,
            sizeof(cfg.fbox_user));
    httpdFindArg(conn->post.buff, "fbox_pass", cfg.fbox_pass,
            sizeof(cfg.fbox_pass));
    httpdFindArg(conn->post.buff, "fbox_addr", cfg.fbox_addr,
            sizeof(cfg.fbox_addr));
    httpdFindArg(conn->post.buff, "fbox_port", cfg.fbox_port,
            sizeof(cfg.fbox_port));

    if(strlen(cfg.fbox_user) > 0
        && strlen(cfg.fbox_pass) > 0
        && strlen(cfg.fbox_addr) > 0
        && strlen(cfg.fbox_port) > 0)
    {
        result = aha_set_cfg(&cfg, true);
        if(result == ESP_OK){
            httpdRedirect(conn, "/");
            goto on_exit;
        }
    }

    httpdRedirect(conn, "/aha/ahacfg.tpl");

on_exit:
    return HTTPD_CGI_DONE;
}

cJSON *lockmode_2_json(enum aha_lock_mode mode)
{
    cJSON *json;
    const char *str;

    json = NULL;

    switch(mode){
    case aha_lock_on:
        str = "on";
        break;
    case aha_lock_off:
        str = "off";
        break;
    case aha_lock_unknown:
    default:
        str = "unknown";
        break;
    }

    json = cJSON_CreateStringReference(str);

    return json;
}

esp_err_t swi_2_json(struct aha_switch *swi, cJSON **obj)
{
    cJSON *json, *tmp;
    const char *str;
    esp_err_t result;

    configASSERT(swi != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    switch(swi->state){
    case aha_swstate_on:
        str = "on";
        break;
    case aha_swstate_off:
        str = "off";
        break;
    case aha_swstate_unknown:
    default:
        str = "unknown";
        break;
    }
    tmp = cJSON_CreateStringReference(str);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "state", tmp);

    switch(swi->mode){
    case aha_switch_auto:
        str = "auto";
        break;
    case aha_switch_manual:
        str = "manual";
        break;
    case aha_switch_unknown:
    default:
        str = "unknown";
        break;
    }
    tmp = cJSON_CreateStringReference(str);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "mode", tmp);

    tmp = lockmode_2_json(swi->lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "lock", tmp);

    tmp = lockmode_2_json(swi->device_lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "device_lock", tmp);

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

esp_err_t pwr_2_json(struct aha_power *pwr, cJSON **obj)
{
    cJSON *json, *tmp;
    esp_err_t result;

    configASSERT(pwr != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    tmp = cJSON_CreateNumber(pwr->power);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "power", tmp);

    tmp = cJSON_CreateNumber(pwr->energy);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "energy", tmp);

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

esp_err_t temp_2_json(struct aha_thermo *temp, cJSON **obj)
{
    cJSON *json, *tmp;
    esp_err_t result;

    configASSERT(temp != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    tmp = cJSON_CreateNumber(temp->temp_c);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "temp_c", tmp);

    tmp = cJSON_CreateNumber(temp->offset);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "offset", tmp);

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

esp_err_t alarm_2_json(struct aha_alarm *alarm, cJSON **obj)
{
    cJSON *json, *tmp;
    const char *str;
    esp_err_t result;

    configASSERT(alarm != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    switch(alarm->mode){
    case aha_alarm_off:
        str = "off";
        break;
    case aha_alarm_on:
        str = "on";
        break;
    case aha_alarm_unknown:
    default:
        str = "unknown";
        break;
    }
    tmp = cJSON_CreateStringReference(str);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "mode", tmp);

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

esp_err_t button_2_json(struct aha_button *btn, cJSON **obj)
{
    cJSON *json, *tmp;
    esp_err_t result;

    configASSERT(btn != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    tmp = cJSON_CreateNumber(btn->last_pressed);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "last_pressed", tmp);

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

esp_err_t hkr_2_json(struct aha_hkr *hkr, cJSON **obj)
{
    cJSON *json, *tmp;
    esp_err_t result;

    configASSERT(hkr != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    tmp = cJSON_CreateNumber(hkr->set_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "set_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->act_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "act_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->comfort_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "comfort_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->eco_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "eco_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->batt_level);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "batt_level", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->batt_low);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "batt_low", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->window_open);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "window_open", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->holiday_act);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "holiday_act", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->summer_act);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "summer_act", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->next_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "next_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->next_change);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "next_change", tmp);

    tmp = lockmode_2_json(hkr->lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "lock", tmp);

    tmp = lockmode_2_json(hkr->device_lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "device_lock", tmp);

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

esp_err_t device_2_json(struct aha_device *dev, cJSON **obj)
{
    cJSON *json, *tmp;
    esp_err_t result;

    configASSERT(dev != NULL);

    result = ESP_OK;
    *obj = NULL;
    json = NULL;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }

    tmp = cJSON_CreateString(dev->type == aha_type_device ? "device" : "group");
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "type", tmp);

    tmp = cJSON_CreateString(dev->name);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "name", tmp);

    tmp = cJSON_CreateString(dev->identifier);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "identifier", tmp);

    tmp = cJSON_CreateString(dev->fw_version);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "fw_version", tmp);

    tmp = cJSON_CreateString(dev->manufacturer);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "manufacturer", tmp);

    tmp = cJSON_CreateString(dev->product_name);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "product_name", tmp);

    tmp = cJSON_CreateNumber(dev->functions);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "functions", tmp);

    tmp = cJSON_CreateNumber(dev->id);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "id", tmp);

    tmp = cJSON_CreateBool(dev->present);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "present", tmp);

    if(dev->swi.present){
        result = swi_2_json(&(dev->swi), &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "switch", tmp);
    }

    if(dev->pwr.present){
        result = pwr_2_json(&(dev->pwr), &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "power", tmp);
    }

    if(dev->temp.present){
        result = temp_2_json(&(dev->temp), &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "thermo", tmp);
    }

    if(dev->alarm.present){
        result = alarm_2_json(&(dev->alarm), &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "alarm", tmp);
    }

    if(dev->button.present){
        result = button_2_json(&(dev->button), &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "button", tmp);
    }

    if(dev->hkr.present){
        result = hkr_2_json(&(dev->hkr), &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "hkr", tmp);
    }

    *obj = json;

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
    }

    return result;
}

cJSON *aha_2_json(struct aha_data *data)
{
    cJSON *json, *devices, *tmp;
    struct aha_device *dev;
    esp_err_t result;

    result = ESP_OK;

    json = cJSON_CreateObject();
    if(json == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateObject() failed.", __func__);
        goto on_exit;
    }

    tmp = cJSON_CreateNumber(data->status);
    if(tmp == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateNumber() failed.", __func__);
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "status", tmp);

    tmp = cJSON_CreateNumber(data->timestamp);
    if(tmp == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateNumber() failed.", __func__);
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "timestamp", tmp);

    tmp = cJSON_CreateBool(data->heat_on);
    if(tmp == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateBool() failed.", __func__);
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "heater_on", tmp);

    if(data->msg && strlen(data->msg) > 0){
        /* Caution! data set must not be released before cJSON object! */
        tmp = cJSON_CreateStringReference(data->msg);
        if(tmp == NULL){
            ESP_LOGE(TAG, "[%s] JSON_CreateNumber() failed.", __func__);
            goto on_exit;
        }
        cJSON_AddItemToObjectCS(json, "message", tmp);
    }

    devices = cJSON_CreateArray();
    if(devices == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateArray() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto on_exit;
    }
    cJSON_AddItemToObjectCS(json, "devices", devices);

    klist_for_each_entry(dev, &(data->dev_head), dev_list){
        result = device_2_json(dev, &tmp);
        if(result != ESP_OK){
            goto on_exit;
        }
        cJSON_AddItemToArray(devices, tmp);
    }

on_exit:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
        json = NULL;
    }

    return json;
}

CgiStatus cgi_aha_dump(HttpdConnData *conn)
{
    struct aha_data *data;
    cJSON *json;
    struct aha_dump *dumper;
    size_t chunk;
    CgiStatus result;

    data = NULL;
    json = NULL;
    dumper = conn->cgiData;
    result = HTTPD_CGI_MORE;

    if(conn->isConnectionClosed){
        result = HTTPD_CGI_DONE;
        goto on_exit;
    }

    if(dumper == NULL){
        httpdStartResponse(conn, 200);
        httpdHeader(conn, "Cache-Control",
                          "no-store, must-revalidate, no-cache, max-age=0");
        httpdHeader(conn, "Expires", "Mon, 01 Jan 1990 00:00:00 GMT");
        httpdHeader(conn, "Content-Type", "application/json; charset=utf-8");
        httpdEndHeaders(conn);

        ESP_LOGD(TAG, "[%s] Allocating Dumper", __func__);
        dumper = calloc(1, sizeof(*dumper));
        if(dumper == NULL){
            ESP_LOGE(TAG, "Out of memory while dumping AHA data");
            result = HTTPD_CGI_DONE;
            goto on_exit;
        }

        data = aha_data_get();
        if(data == NULL){
            ESP_LOGE(TAG, "[%s] No AHA data", __func__);
            result = HTTPD_CGI_DONE;
            goto on_exit;
        }

        json = aha_2_json(data);
        if(json == NULL){
            ESP_LOGE(TAG, "[%s] Creating JSON failed.", __func__);
            result = HTTPD_CGI_DONE;
            goto on_exit;
        }

        dumper->str = cJSON_Print(json);
        if(dumper->str == NULL){
            ESP_LOGE(TAG, "[%s] Printing JSON failed", __func__);
            result = HTTPD_CGI_DONE;
            goto on_exit;
        }

        conn->cgiData = dumper;
    }

    chunk = MIN((strlen(dumper->str) - dumper->offset), 128);

    if(chunk > 0){
        httpdSend(conn, dumper->str + dumper->offset, chunk);
        dumper->offset += chunk;
    }

    if(dumper->offset >= strlen(dumper->str)){
        result = HTTPD_CGI_DONE;
    }

on_exit:
    /* json may contain reference to data->msg, so it must be released first! */
    if(json != NULL){
        cJSON_Delete(json);
    }

    if(data != NULL){
        aha_data_release(data);
    }

    if(result == HTTPD_CGI_DONE && dumper != NULL){
        ESP_LOGD(TAG, "[%s] Cleaning up", __func__);

        if(dumper->str != NULL){
            free(dumper->str);
        }

        free(dumper);
    }

    return result;
}

