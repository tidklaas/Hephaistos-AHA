/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
   Cgi/template routines for the /wifi url.
 */

#include <stdarg.h>
#include <esp_wifi_types.h>
#include <esp_wifi.h>
#include <esp_log.h>
#include <libesphttpd/esp.h>
#include <heph_cgi.h>
#include <hephaistos.h>
#include <avm_aha.h>
#include <http_srv.h>
#include <cJSON.h>
#include <sys/param.h>

static const char *TAG = "CGI";
CgiStatus cgi_redirect(HttpdConnData *conn)
{
    struct heph_wifi_cfg heph_cfg;
    struct http_srv_cfg http_cfg;
    struct aha_cfg aha_cfg;
    esp_err_t result;

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
        goto err_out;
    }

    /* Check if NVS contains valid configurations for HTTP user, Wifi
       and AHA. Force user to enter data if none is found. */

    /* HTTP user config */
    result = http_get_cfg(&http_cfg, cfg_nvs);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/user/");
        goto err_out;
    }

    /* WiFi config */
    result = heph_get_cfg(&heph_cfg, cfg_nvs);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/wifi/");
        goto err_out;
    }

    /* AHA config */
    result = aha_get_cfg(&aha_cfg, cfg_nvs);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/aha/ahacfg.tpl");
        goto err_out;
    }

    httpdRedirect(conn, "/aha/");

err_out:
    return HTTPD_CGI_DONE;
}

extern struct http_srv_cfg http_cfg;
int tpl_user(HttpdConnData *conn, char *token, void **arg)
{
    char buff[128];

    if(token == NULL){
        goto err_out;
    }

    memset(buff, 0x0, sizeof(buff));

    if(strcmp(token, "user") == 0){
        strlcpy(buff, http_cfg.user, sizeof(buff));
    }else if(strcmp(token, "pass") == 0){
        strlcpy(buff, http_cfg.pass, sizeof(buff));
    }

    httpdSend(conn, buff, -1);

err_out:
    return HTTPD_CGI_DONE;
}

CgiStatus cgi_user_set(HttpdConnData *conn)
{
    struct http_srv_cfg cfg;
    esp_err_t result;

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
        return HTTPD_CGI_DONE;
    }

    memset(&cfg, 0x0, sizeof(cfg));

    httpdFindArg(conn->post.buff, "user", cfg.user, sizeof(cfg.user));
    httpdFindArg(conn->post.buff, "pass", cfg.pass, sizeof(cfg.pass));

    if(strlen(cfg.user) > 0 && strlen(cfg.pass) > 0){
        result = http_set_cfg(&cfg, true);
        if(result == ESP_OK){
            httpdRedirect(conn, "/");
            goto err_out;
        }
    }

    httpdRedirect(conn, "/user");

err_out:
    return HTTPD_CGI_DONE;
}

int tpl_ahacfg(HttpdConnData *conn, char *token, void **arg)
{
    char buff[128];
    struct aha_cfg cfg;
    esp_err_t result;

    memset(buff, 0x0, sizeof(buff));
    strlcpy(buff, "<INVALID>", sizeof(buff));

    if(token == NULL){
        goto err_out;
    }

    ESP_LOGI(TAG,"[%s] Token: %s", __func__, token);

    /* Get currently active AHA configuration */
    result = aha_get_cfg(&cfg, cfg_ram);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Fetching current AHA config failed.", __func__);
        goto err_out;
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

err_out:
    httpdSend(conn, buff, -1);

    return HTTPD_CGI_DONE;
}

CgiStatus cgi_aha_setcfg(HttpdConnData *conn)
{
    struct aha_cfg cfg;
    esp_err_t result;

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
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

    if(   strlen(cfg.fbox_user) > 0
       && strlen(cfg.fbox_pass) > 0
       && strlen(cfg.fbox_addr) > 0
       && strlen(cfg.fbox_port) > 0
      )
    {
        result = aha_set_cfg(&cfg, true);
        if(result == ESP_OK){
            httpdRedirect(conn, "/");
            goto err_out;
        }
    }

    httpdRedirect(conn, "/aha/ahacfg.tpl");

err_out:
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
        goto err_out;
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
        goto err_out;
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
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "mode", tmp);

    tmp = lockmode_2_json(swi->lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "lock", tmp);

    tmp = lockmode_2_json(swi->device_lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "device_lock", tmp);

    *obj = json;

err_out:
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
        goto err_out;
    }

    tmp = cJSON_CreateNumber(pwr->power);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "power", tmp);

    tmp = cJSON_CreateNumber(pwr->energy);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "energy", tmp);

    *obj = json;

err_out:
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
        goto err_out;
    }
    
    tmp = cJSON_CreateNumber(temp->temp_c);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "temp_c", tmp);

    tmp = cJSON_CreateNumber(temp->offset);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "offset", tmp);

    *obj = json;

err_out:
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
        goto err_out;
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
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "mode", tmp);

    *obj = json;

err_out:
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
        goto err_out;
    }
    
    tmp = cJSON_CreateNumber(btn->last_pressed);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "last_pressed", tmp);

    *obj = json;

err_out:
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
        goto err_out;
    }

    tmp = cJSON_CreateNumber(hkr->set_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "set_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->act_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "act_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->comfort_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "comfort_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->eco_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "eco_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->batt_low);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "batt_low", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->window_open);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "window_open", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->next_temp);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "next_temp", tmp);
    *obj = json;

    tmp = cJSON_CreateNumber(hkr->next_change);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "next_change", tmp);

    tmp = lockmode_2_json(hkr->lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "lock", tmp);

    tmp = lockmode_2_json(hkr->device_lock);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "device_lock", tmp);
    
    *obj = json;

err_out:
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
        goto err_out;
    }

    tmp = cJSON_CreateString(dev->type == aha_type_device ? "device" : "group");    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "type", tmp);
    
    tmp = cJSON_CreateString(dev->name);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "name", tmp);

    tmp = cJSON_CreateString(dev->identifier);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "identifier", tmp);

    tmp = cJSON_CreateString(dev->fw_version);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "fw_version", tmp);

    tmp = cJSON_CreateString(dev->manufacturer);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "manufacturer", tmp);

    tmp = cJSON_CreateString(dev->product_name);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "product_name", tmp);

    tmp = cJSON_CreateNumber(dev->functions);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "functions", tmp);

    tmp = cJSON_CreateNumber(dev->id);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "id", tmp);

    tmp = cJSON_CreateBool(dev->present);
    if(tmp == NULL){
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "present", tmp);

    if(dev->swi.present){
        result = swi_2_json(&(dev->swi), &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToObjectCS(json, "switch", tmp);
    }

    if(dev->pwr.present){
        result = pwr_2_json(&(dev->pwr), &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToObjectCS(json, "power", tmp);
    }

    if(dev->temp.present){
        result = temp_2_json(&(dev->temp), &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToObjectCS(json, "thermo", tmp);
    }

    if(dev->alarm.present){
        result = alarm_2_json(&(dev->alarm), &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToObjectCS(json, "alarm", tmp);
    }

    if(dev->button.present){
        result = button_2_json(&(dev->button), &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToObjectCS(json, "button", tmp);
    }

    if(dev->hkr.present){
        result = hkr_2_json(&(dev->hkr), &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToObjectCS(json, "hkr", tmp);
    }

    *obj = json;

err_out:
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
        goto err_out;
    }

    devices = cJSON_CreateArray();
    if(devices == NULL){
        ESP_LOGE(TAG, "[%s] JSON_CreateArray() failed.", __func__);
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }
    cJSON_AddItemToObjectCS(json, "devices", devices);

    klist_for_each_entry(dev, &(data->dev_head), dev_list){
        result = device_2_json(dev, &tmp);
        if(result != ESP_OK){
            goto err_out;
        }
        cJSON_AddItemToArray(devices, tmp);
    }


err_out:
    if(result != ESP_OK && json != NULL){
        cJSON_Delete(json);
        json = NULL;
    }

    return json;
}

struct aha_dump {
    struct aha_data *data;
    char *str;
    size_t offset;
};

CgiStatus cgi_aha_dump(HttpdConnData *conn)
{
    struct aha_device *dev, *grp;
    cJSON *json;
    struct aha_dump *dumper;
    size_t chunk;
    CgiStatus result;

    json = NULL;
    dumper = conn->cgiData;
    result = HTTPD_CGI_MORE;

    ESP_LOGD(TAG, "[%s] Called", __func__);

    if(conn->isConnectionClosed){
        ESP_LOGE(TAG, "[%s] Conn closed", __func__);
        result = HTTPD_CGI_DONE;
        goto err_out;
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
            goto err_out;
        }

        dumper->data = aha_data_get();
        if(dumper->data == NULL){
            ESP_LOGE(TAG, "[%s] No AHA data", __func__);
            result = HTTPD_CGI_DONE;
            goto err_out;
        }

        json = aha_2_json(dumper->data);
        if(json == NULL){
            ESP_LOGE(TAG, "[%s] Creating JSON failed.", __func__);
            result = HTTPD_CGI_DONE;
            goto err_out;
        }

        dumper->str = cJSON_Print(json);
        if(dumper->str == NULL){
            ESP_LOGE(TAG, "[%s] Printing JSON failed", __func__);
            result = HTTPD_CGI_DONE;
            goto err_out;
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

err_out:
    if(json != NULL){
        cJSON_Delete(json);
    }

    if(result == HTTPD_CGI_DONE && dumper != NULL){
        ESP_LOGD(TAG, "[%s] Cleaning up", __func__);
        if(dumper->data != NULL){
            aha_data_release(dumper->data);
        }

        if(dumper->str != NULL){
            free(dumper->str);
        }

        free(dumper);
    }

    return result;
}

