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

#include <esp_log.h>
#include <nvs_flash.h>
#include <tcpip_adapter.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>
#include <freertos/event_groups.h>

#include <libesphttpd/esp.h>
#include <libesphttpd/httpd.h>
//#include <libesphttpd/cgiwifi.h>
#include <libesphttpd/cgiflash.h>
#include <libesphttpd/auth.h>
#include <libesphttpd/captdns.h>
#include <libesphttpd/httpd-freertos.h>
#include <libesphttpd/route.h>

#include <espfs.h>
#include <espfs_image.h>
#include <libesphttpd/httpd-espfs.h>

#include <hephaistos.h>
#include <avm_aha.h>
#include <heph_cgi.h>
#include <http_srv.h>

#define TAG "http_srv"

#define LISTEN_PORT     80u
#define MAX_CONNECTIONS 32u

struct http_srv_cfg http_cfg;
static SemaphoreHandle_t http_cfg_lock = NULL;

static char conn_mem[sizeof(RtosConnType) * MAX_CONNECTIONS];
static HttpdFreertosInstance httpd_instance;

int auth_func(HttpdConnData *conn, int idx, char *user, int user_len, char *pass, int pass_len)
{
    if(idx > 0){
        return 0;
    }

    if(xSemaphoreTake(http_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        return 0;
    }
    
    strlcpy(user, http_cfg.user, user_len);
    strlcpy(pass, http_cfg.pass, pass_len);
    
    xSemaphoreGive(http_cfg_lock);
   
    return 1;
}


#define OTA_FLASH_SIZE_K 1024
#define OTA_TAGNAME "generic"

CgiUploadFlashDef upload_params={
	.type=CGIFLASH_TYPE_FW,
	.fw1Pos=0x1000,
	.fw2Pos=((OTA_FLASH_SIZE_K*1024)/2)+0x1000,
	.fwSize=((OTA_FLASH_SIZE_K*1024)/2)-0x1000,
	.tagName=OTA_TAGNAME
};

HttpdBuiltInUrl urls_setup[]={
	ROUTE_AUTH("/*", auth_func),
	ROUTE_CGI("/", cgi_redirect),
	ROUTE_CGI("/index.html", cgi_redirect),

	ROUTE_REDIRECT("/wifi", "/wifi/wifi.tpl"),
	ROUTE_REDIRECT("/wifi/", "/wifi/wifi.tpl"),
	ROUTE_TPL("/wifi/wifi.tpl", tpl_wlan),
	ROUTE_CGI("/wifi/wifiscan.cgi", cgi_wifi_scan),
	ROUTE_CGI("/wifi/connect.cgi", cgi_wifi_connect),
	ROUTE_CGI("/wifi/connstatus.cgi", cgi_wifi_conn_status),
	ROUTE_CGI("/wifi/setmode.cgi", cgi_wifi_set_mode),
	
	ROUTE_REDIRECT("/user", "/user/user.tpl"),
	ROUTE_REDIRECT("/user/", "/user/user.tpl"),
    ROUTE_TPL("/user/user.tpl", tpl_user),
    ROUTE_CGI("/user/setuser.cgi", cgi_user_set),

	ROUTE_REDIRECT("/aha", "/aha/ahadump.cgi"),
	ROUTE_REDIRECT("/aha/", "/aha/ahadump.cgi"),
    ROUTE_CGI("/aha/ahadump.cgi", cgi_aha_dump),
    ROUTE_TPL("/aha/ahacfg.tpl", tpl_ahacfg),
    ROUTE_CGI("/aha/ahasetcfg.cgi", cgi_aha_setcfg),
	
	ROUTE_REDIRECT("/flash", "/flash/index.html"),
	ROUTE_REDIRECT("/flash/", "/flash/index.html"),
	ROUTE_CGI_ARG("/flash/next", cgiGetFirmwareNext, &upload_params),
	ROUTE_CGI_ARG("/flash/upload", cgiUploadFirmware, &upload_params),
	ROUTE_CGI("/flash/reboot", cgiRebootFirmware),

    ROUTE_FILESYSTEM(),

	ROUTE_END()
};

esp_err_t http_set_cfg(struct http_srv_cfg *cfg, bool reload)
{
    esp_err_t result;
    nvs_handle handle;

    if(http_cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    result = nvs_open(HTTP_NVS_NAMESPC, NVS_READWRITE, &handle);
    if(result != ESP_OK){
        return result;
    }

    if(xSemaphoreTake(http_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }

    result = nvs_set_str(handle, "http_user", cfg->user);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_set_str(handle, "http_pass", cfg->pass);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_commit(handle);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    if(reload){
        strlcpy(http_cfg.user, cfg->user, sizeof(http_cfg.user));
        strlcpy(http_cfg.pass, cfg->pass, sizeof(http_cfg.pass));
    }

err_out_unlock:
    xSemaphoreGive(http_cfg_lock);

err_out:
    nvs_close(handle);

    return result;
}

esp_err_t http_get_cfg(struct http_srv_cfg *cfg, enum cfg_load_type from)
{
    esp_err_t result;
    size_t len;
    nvs_handle handle;

    if(from != cfg_nvs && from != cfg_ram){
        return ESP_ERR_INVALID_ARG;
    }

    if(http_cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    if(from == cfg_nvs){
        result = nvs_open(HTTP_NVS_NAMESPC, NVS_READONLY, &handle);
        if(result != ESP_OK){
            return result;
        }
    }

    if(xSemaphoreTake(http_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }

    if(from == cfg_ram){
        memmove(cfg, &http_cfg, sizeof(*cfg));
        result = ESP_OK;
        goto err_out_unlock;
    }

    memset(cfg, 0x0, sizeof(*cfg));

    len = sizeof(cfg->user);
    result = nvs_get_str(handle, "http_user", cfg->user, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    len = sizeof(cfg->pass);
    result = nvs_get_str(handle, "http_pass", cfg->pass, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

err_out_unlock:
    xSemaphoreGive(http_cfg_lock);

err_out:
    if(from == cfg_nvs){
        nvs_close(handle);
    }

    return result;
}

esp_err_t http_srv_init(void)
{
    HttpdInitStatus status;
    esp_err_t result;

    result = ESP_OK;

    http_cfg_lock = xSemaphoreCreateMutex();
    if(http_cfg_lock == NULL){
        ESP_LOGE(TAG, "Creating http_cfg_lock failed.");
        goto err_out;
    }

    if(espFsInit((void*)(image_espfs_start)) != ESPFS_INIT_RESULT_OK){
        result = ESP_FAIL;
        goto err_out;
    }

    do{
        result = http_get_cfg(&http_cfg, cfg_nvs);
        if(result != ESP_OK && result != ESP_ERR_TIMEOUT){
            strlcpy(http_cfg.user, "hephaistos", sizeof(http_cfg.user));
            strlcpy(http_cfg.pass, "fire", sizeof(http_cfg.pass));
        }
    }while(result == ESP_ERR_TIMEOUT);

    status = httpdFreertosInit(&httpd_instance,
	                           urls_setup,
	                           LISTEN_PORT,
	                           conn_mem,
	                           MAX_CONNECTIONS,
	                           HTTPD_FLAG_NONE);

    if(status != InitializationSuccess){
       result = ESP_FAIL;
       goto err_out;
    }

    httpdFreertosStart(&httpd_instance);

err_out:
    return result;
}
