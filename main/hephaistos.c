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
#include <avm_aha.h>

#include <sdkconfig.h>

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

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
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
#define TIMEZONE        CONFIG_TIMEZONE

#define TWDT_TIMEOUT_S          300
#define TASK_RESET_PERIOD_S     5

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

static const char *TAG = "hephaistos";

/* The event group allows multiple bits for each event,
 * but we only care about one event - are we connected
 * to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

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

void get_time(void)
{
    time_t now;
    struct tm timeinfo;
    char strftime_buf[64];

    time(&now);
    localtime_r(&now, &timeinfo);

    // Is time set? If not, tm_year will be (1970 - 1900).
    if (timeinfo.tm_year < (2016 - 1900)) {
        ESP_LOGI(TAG, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
        obtain_time();
    }

    // Set timezone to Eastern Standard Time and print local time
    setenv("TZ", TIMEZONE, 1);
    tzset();
    // update 'now' variable with current time
    time(&now);
    localtime_r(&now, &timeinfo);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);
    ESP_LOGI(TAG, "The current date/time is: %s", strftime_buf);

}

void app_main()
{
    struct aha_cfg aha_cfg;
    struct aha_data *data;
    esp_err_t result;

    result = nvs_flash_init();
    if(result == ESP_ERR_NVS_NO_FREE_PAGES){
        nvs_flash_erase();
        result = nvs_flash_init();
    }

    if(result != ESP_OK){
        ESP_LOGE(TAG, "NVS init failed");
        goto err_out;
    }

    initialise_wifi();
    get_time();
    xTaskCreate(&avm_aha_task, "avm_aha_task", 8192, NULL, 5, NULL);

    do{
        ESP_LOGI(TAG, "Fetching AHA config.");
        result = aha_get_cfg(&aha_cfg);
        if(result != ESP_OK){
            ESP_LOGI(TAG, "AHA config not ready, retrying in 5 seconds");
            sleep(5);
        }
    }while(result == ESP_ERR_TIMEOUT);

    if(result != ESP_OK){
        ESP_LOGI(TAG, "Setting default AHA config");
        strlcpy(aha_cfg.fbox_user, CONFIG_FBOX_USER, sizeof(aha_cfg.fbox_user));
        strlcpy(aha_cfg.fbox_pass, CONFIG_FBOX_PASSWORD, sizeof(aha_cfg.fbox_pass));
        strlcpy(aha_cfg.fbox_addr, CONFIG_FBOX_ADDR, sizeof(aha_cfg.fbox_addr));
        strlcpy(aha_cfg.fbox_port, CONFIG_FBOX_PORT, sizeof(aha_cfg.fbox_port));

        while(aha_set_cfg(&aha_cfg, true) != ESP_OK){
            ESP_LOGE(TAG, "Setting AHA config failed, retrying in 5 seconds.");
            sleep(5);
        }
    }

    aha_task_resume();

    srand(esp_get_free_heap_size());
    data = NULL;
    while(1){
        sleep(rand() % 5);
        ESP_LOGI(TAG, "Fetching data");
        data = aha_data_get();
        sleep(rand() % 15);
        ESP_LOGI(TAG, "Releasing data");
        ESP_LOGI(TAG, "Free heap before: 0x%x", esp_get_free_heap_size());
        aha_data_release(data);
        ESP_LOGI(TAG, "Free heap after: 0x%x", esp_get_free_heap_size());
    }

err_out:
    ESP_LOGE(TAG, "Enter error state");
    while(1)
        ;
}
