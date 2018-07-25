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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
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

#include <sdkconfig.h>

#include <hephaistos.h>
#include <avm_aha.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/event_groups.h>
#include <esp_wifi.h>
#include <esp_event_loop.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <driver/gpio.h>
#include <driver/ledc.h>
#include <esp_intr_alloc.h>
#include <rom/rtc.h>

#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <lwip/dns.h>

#include <apps/sntp/sntp.h>

//#include <libesphttpd/cgiwifi.h>
#include <http_srv.h>

#define TIMEZONE        CONFIG_TIMEZONE
#define GPIO_HEAT       CONFIG_GPIO_HEAT
#define GPIO_LED        CONFIG_GPIO_LED
#define GPIO_FW_RESET   CONFIG_GPIO_FW_RESET

#define TWDT_TIMEOUT_S          300
#define TASK_RESET_PERIOD_S     5
#define FW_RESET_TIME           10

static struct heph_wifi_cfg wifi_cfg;
static SemaphoreHandle_t wifi_cfg_lock = NULL;

static EventGroupHandle_t heph_event_group;
static TimerHandle_t heph_timer = NULL;
static TimerHandle_t fwrst_timer = NULL;

#define HEPH_MAGIC  0x48455048  // "HEPH"

__NOINIT_ATTR static volatile struct _restart_marker {
    uint32_t magic;
    uint32_t count;
} restart_marker;

static const char *TAG = "hephaistos";

static struct heph_state {
    wifi_config_t ap_cfg;
    wifi_config_t st_cfg;
    wifi_mode_t mode;
} heph_state;

static const int BIT_TRIGGER       = BIT0;
static const int BIT_STA_STARTED   = BIT1;
static const int BIT_STA_CONNECTED = BIT2;
static const int BIT_AP_STARTED    = BIT3;
static const int BIT_AP_CONNECTED  = BIT4;
static const int BIT_RELOAD_CFG    = BIT5;
static const int BIT_NTP_SYNC      = BIT6;
static const int BIT_AHA_CFG       = BIT7;
static const int BIT_AHA_RUN       = BIT8;
static const int BIT_HTTP_RUN      = BIT9;
static const int BIT_FW_RESET      = BIT10;

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    tcpip_adapter_ip_info_t ap_ip_info;
    esp_err_t result;

    switch(event->event_id){
    case SYSTEM_EVENT_STA_START:
        xEventGroupSetBits(heph_event_group, BIT_STA_STARTED);
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_STOP:
        xEventGroupClearBits(heph_event_group, BIT_STA_STARTED);
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(heph_event_group, BIT_STA_CONNECTED);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
         * auto-reassociate. */
        xEventGroupClearBits(heph_event_group, BIT_STA_CONNECTED);
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_AP_START:
        xEventGroupSetBits(heph_event_group, BIT_AP_STARTED);
        result = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_AP, &ap_ip_info);
        if(result == ESP_OK){
            ESP_LOGI(TAG, "~~~~~~~~~~~");
            ESP_LOGI(TAG, "IP:" IPSTR, IP2STR(&ap_ip_info.ip));
            ESP_LOGI(TAG, "MASK:" IPSTR, IP2STR(&ap_ip_info.netmask));
            ESP_LOGI(TAG, "GW:" IPSTR, IP2STR(&ap_ip_info.gw));
            ESP_LOGI(TAG, "~~~~~~~~~~~");
        }
        break;
    case SYSTEM_EVENT_AP_STOP:
        xEventGroupClearBits(heph_event_group, BIT_AP_STARTED);
        break;
    case SYSTEM_EVENT_AP_STACONNECTED:
        ESP_LOGI(TAG, "station: " MACSTR " join, AID=%d\n",
                 MAC2STR(event->event_info.sta_connected.mac),
                 event->event_info.sta_connected.aid);

        xEventGroupSetBits(heph_event_group, BIT_AP_CONNECTED);
        break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
        ESP_LOGI(TAG, "station: " MACSTR " leave, AID=%d\n",
                 MAC2STR(event->event_info.sta_disconnected.mac),
                 event->event_info.sta_disconnected.aid);

        xEventGroupClearBits(heph_event_group, BIT_AP_CONNECTED);
        break;
    case SYSTEM_EVENT_SCAN_DONE:
        wifi_scan_done_cb();
        break;
    default:
        break;
    }

    /* Wake up main task */
    xEventGroupSetBits(heph_event_group, BIT_TRIGGER);

    return ESP_OK;
}

static void
init_wifi_cfg(struct heph_wifi_cfg *heph_cfg, struct heph_state *state)
{
    wifi_config_t *cfg;

    cfg = &(state->ap_cfg);
    memset(cfg, 0x0, sizeof(*cfg));

    strlcpy((char *) cfg->ap.ssid, HEPH_AP_SSID, sizeof(cfg->ap.ssid));
    cfg->ap.max_connection = 1;
    cfg->ap.authmode = WIFI_AUTH_OPEN;

    cfg = &(state->st_cfg);
    memset(cfg, 0x0, sizeof(*cfg));

    if(strlen(heph_cfg->ssid) > 0 && strlen(heph_cfg->pass) > 0){
        state->mode = WIFI_MODE_STA;
        strlcpy((char *) cfg->sta.ssid, heph_cfg->ssid, sizeof(cfg->sta.ssid));
        strlcpy((char *) cfg->sta.password, heph_cfg->pass,
                sizeof(cfg->sta.password));
    } else {
        state->mode = WIFI_MODE_APSTA;
    }
}

static esp_err_t config_wifi(struct heph_state *state)
{
    EventBits_t events;
    esp_err_t result;

#if 0
    result = esp_wifi_stop();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_stop() failed", __func__);
        goto err_out;
    }
#endif

    result = esp_wifi_set_mode(state->mode);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_set_mode() failed", __func__);
        goto err_out;
    }

    result = esp_wifi_set_config(ESP_IF_WIFI_STA, &(state->st_cfg));
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_set_config() failed for STA", __func__);
        goto err_out;
    }

    if(state->mode == WIFI_MODE_APSTA){
        result = esp_wifi_set_config(ESP_IF_WIFI_AP, &(state->ap_cfg));
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_set_config() failed for AP", __func__);
            goto err_out;
        }
    }

    events = xEventGroupGetBits(heph_event_group);
    if(!(events & BIT_STA_STARTED)){
        result = esp_wifi_start();
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_start() failed", __func__);
            goto err_out;
        }
    }

err_out:
    return result;
}

static esp_err_t init_wifi(void)
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t result;

    tcpip_adapter_init();

    result = esp_event_loop_init(event_handler, NULL);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_event_loop_init() failed", __func__);
        goto err_out;
    }

    result = esp_wifi_init(&cfg);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_init() failed", __func__);
        goto err_out;
    }

    result = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_set_storage() failed", __func__);
        goto err_out;
    }

err_out:
    return result;
}

esp_err_t heph_connected(void)
{
    wifi_ap_record_t wapr;
    tcpip_adapter_ip_info_t info;
    EventBits_t events;
    esp_err_t result;

    /* Skip data retrieval if we have connectivity or network issues */
    events = xEventGroupGetBits(heph_event_group);
    if(!(events & BIT_STA_CONNECTED)){
        result = ESP_ERR_NOT_FOUND;
        goto err_out;
    }

    result = esp_wifi_sta_get_ap_info(&wapr);
    if(result != ESP_OK){
        goto err_out;
    }

    result = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &info);
    if(result != ESP_OK || info.ip.addr == IPADDR_ANY){
        result = ESP_ERR_NOT_FOUND;
        goto err_out;
    }

err_out:
    return result;
}

static void update_sntp(void)
{
    time_t now;
    struct tm tm;
    EventBits_t events;
    bool running;
    char buff[32];
    esp_err_t result;

    running = sntp_enabled();

    result = heph_connected();
    if(result != ESP_OK){
        if(running){
            ESP_LOGI(TAG, "Stopping SNTP");
            sntp_stop();
        }
        xEventGroupClearBits(heph_event_group, BIT_NTP_SYNC);
    } else {
        if(!running){
            ESP_LOGI(TAG, "Starting SNTP");
            sntp_setoperatingmode(SNTP_OPMODE_POLL);
            sntp_setservername(0, "pool.ntp.org");
            sntp_init();
        }


        events =  xEventGroupGetBits(heph_event_group);
        if(!(events & BIT_NTP_SYNC)){
            time(&now);
            memset(&tm, 0x0, sizeof(tm));
            localtime_r(&now, &tm);

            if(tm.tm_year > (2016 - 1900)){
                ESP_LOGI(TAG, "[%s] Got NTP time sync: %s", __func__, asctime_r(&tm, buff));
                xEventGroupSetBits(heph_event_group, BIT_NTP_SYNC);
            }
        }
    }
}

esp_err_t heph_set_cfg(struct heph_wifi_cfg *cfg, bool reload)
{
    esp_err_t result;
    nvs_handle handle;

    if(wifi_cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    if((strlen(cfg->ssid) == 0) || (strlen(cfg->pass) == 0)){
        ESP_LOGE(TAG, "[%s] Config invalid", __func__);
        return ESP_ERR_INVALID_ARG;
    }

    result = nvs_open(HEPH_NVS_NAMESPC, NVS_READWRITE, &handle);
    if(result != ESP_OK){
        return result;
    }

    if(xSemaphoreTake(wifi_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }

    result = nvs_set_str(handle, "wifi_ssid", cfg->ssid);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    result = nvs_set_str(handle, "wifi_pass", cfg->pass);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    /* Timezone is optional */
    if(strlen(cfg->tz) > 0){
        result = nvs_set_str(handle, "timezone", cfg->tz);
        if(result != ESP_OK){
            goto err_out_unlock;
        }
    }

    result = nvs_commit(handle);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    if(reload){
        xEventGroupSetBits(heph_event_group, (BIT_RELOAD_CFG | BIT_TRIGGER));
    }

err_out_unlock:
    xSemaphoreGive(wifi_cfg_lock);

err_out:
    nvs_close(handle);

    return result;
}

esp_err_t heph_get_cfg(struct heph_wifi_cfg *cfg, enum cfg_load_type from)
{
    esp_err_t result;
    size_t len;
    nvs_handle handle;

    if(from != cfg_nvs && from != cfg_ram){
        return ESP_ERR_INVALID_ARG;
    }

    if(wifi_cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    if(from == cfg_nvs){
        result = nvs_open(HEPH_NVS_NAMESPC, NVS_READONLY, &handle);
        if(result != ESP_OK){
            return result;
        }
    }

    if(xSemaphoreTake(wifi_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }


    if(from == cfg_ram){
        memmove(cfg, &wifi_cfg, sizeof(*cfg));
        result = ESP_OK;
        goto err_out_unlock;
    }

    memset(cfg, 0x0, sizeof(*cfg));

    len = sizeof(cfg->ssid);
    result = nvs_get_str(handle, "wifi_ssid", cfg->ssid, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    len = sizeof(cfg->pass);
    result = nvs_get_str(handle, "wifi_pass", cfg->pass, &len);
    if(result != ESP_OK){
        goto err_out_unlock;
    }

    /* Try to read timezone. Fall back to default if not set */
    len = sizeof(cfg->tz);
    result = nvs_get_str(handle, "timezone", cfg->tz, &len);
    if((result != ESP_OK) || (strlen(cfg->tz) == 0)){
        strlcpy(cfg->tz, TIMEZONE, sizeof(cfg->tz));
        result = ESP_OK;
    }

err_out_unlock:
    xSemaphoreGive(wifi_cfg_lock);

err_out:
    if(from == cfg_nvs){
        nvs_close(handle);
    }

    return result;
}

static esp_err_t reload_cfg(void)
{
    esp_err_t result;
    struct heph_wifi_cfg cfg;

    result = heph_get_cfg(&cfg, cfg_nvs);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] heph_get_cfg() failed", __func__);
        goto err_out;
    }

    if(xSemaphoreTake(wifi_cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto err_out;
    }

    memmove(&wifi_cfg, &cfg, sizeof(wifi_cfg));

    xSemaphoreGive(wifi_cfg_lock);

    setenv("TZ", wifi_cfg.tz, 1);
    tzset();

    init_wifi_cfg(&wifi_cfg, &heph_state);

    result = config_wifi(&heph_state);

err_out:
    return result;
}

static void timer_cb(TimerHandle_t timer)
{
    if(timer == fwrst_timer){
        xEventGroupSetBits(heph_event_group, BIT_FW_RESET);
    }

    xEventGroupSetBits(heph_event_group, BIT_TRIGGER);
}

static esp_err_t check_aha_cfg(void)
{
    struct aha_cfg aha_cfg;
    esp_err_t result;

    ESP_LOGI(TAG, "Fetching AHA config.");
    result = aha_get_cfg(&aha_cfg, cfg_nvs);
    if(result == ESP_OK){
        xEventGroupSetBits(heph_event_group, BIT_AHA_CFG);
        goto err_out;
    }

err_out:
    return result;
}


static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    uint32_t gpio;
    BaseType_t result, task_woken;

    gpio = (uint32_t) arg;
    result = pdFAIL;
    task_woken = pdFALSE;

    if(gpio == GPIO_FW_RESET){
        result = xEventGroupSetBitsFromISR(heph_event_group,
                                           BIT_TRIGGER,
                                           &task_woken);
    }

    if(result != pdFAIL && task_woken != pdFALSE){
        portYIELD_FROM_ISR();
    }
}

static esp_err_t setup_gpios(void)
{
    gpio_config_t cfg;
    esp_err_t result;

    result = ESP_OK;

    result = gpio_install_isr_service(0);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] gpio_install_isr_service() failed", __func__);
        goto err_out;
    }

    result = gpio_isr_handler_add(GPIO_FW_RESET, gpio_isr_handler,
                                  (void*) GPIO_FW_RESET);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] gpio_isr_handler_add() failed", __func__);
        goto err_out;
    }

    memset(&cfg, 0x0, sizeof(cfg));
    cfg.pin_bit_mask = (1 << GPIO_FW_RESET);
    cfg.mode = GPIO_MODE_INPUT;
    cfg.pull_up_en = GPIO_PULLUP_ENABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_INTR_ANYEDGE;

    result = gpio_config(&cfg);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] gpio_config() failed for reset button", __func__);
        goto err_out;
    }

    memset(&cfg, 0x0, sizeof(cfg));
    cfg.pin_bit_mask = (uint64_t)((1ULL << GPIO_HEAT) | (1ULL << GPIO_LED));
    cfg.mode = GPIO_MODE_OUTPUT;
    cfg.pull_up_en = GPIO_PULLUP_DISABLE;
    cfg.pull_down_en = GPIO_PULLDOWN_DISABLE;
    cfg.intr_type = GPIO_PIN_INTR_DISABLE;

    result = gpio_config(&cfg);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] gpio_config() failed for HEAT/LED", __func__);
        goto err_out;
    }

err_out:
    return result;
}

void heph_led_set(bool on)
{
    gpio_set_level(GPIO_LED, on ? 1 : 0);
}

void heph_heat_set(bool on)
{
    gpio_set_level(GPIO_HEAT, on ? 1 : 0);
}

static bool check_fwreset(void)
{
    EventBits_t events;
    BaseType_t timer_running;
    ledc_timer_config_t ledc_timer;
    ledc_channel_config_t ledc_channel;
    bool do_reset;
    static unsigned int reset_cnt = 0;

    do_reset = false;
    events = xEventGroupClearBits(heph_event_group, BIT_FW_RESET);
    timer_running = xTimerIsTimerActive(fwrst_timer);

    if(gpio_get_level(GPIO_FW_RESET) == 1){
        if(timer_running != pdFALSE){
            (void) xTimerStop(fwrst_timer, portMAX_DELAY);
            ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_TIMER_0, 0);
            gpio_matrix_out(GPIO_LED, SIG_GPIO_OUT_IDX, 0, 0);
            ESP_LOGI(TAG, "[%s] Aborting FW reset", __func__);
        }
    } else {
        if(timer_running == pdFALSE){
            ESP_LOGI(TAG, "[%s] Starting FW reset timer", __func__);
            (void) xTimerReset(fwrst_timer, portMAX_DELAY);

            reset_cnt = 0;

            ledc_timer.duty_resolution = LEDC_TIMER_20_BIT;
            ledc_timer.freq_hz = 5;
            ledc_timer.speed_mode = LEDC_LOW_SPEED_MODE;
            ledc_timer.timer_num = LEDC_TIMER_0;

            ledc_timer_config(&ledc_timer);

            ledc_channel.channel = LEDC_CHANNEL_0;
            ledc_channel.duty = (1 << 19);
            ledc_channel.gpio_num = GPIO_LED;
            ledc_channel.speed_mode = LEDC_LOW_SPEED_MODE;
            ledc_channel.timer_sel = LEDC_TIMER_0;

            ledc_channel_config(&ledc_channel);
        }

        if((events & BIT_FW_RESET) == BIT_FW_RESET){
            ++reset_cnt;
        }


        ESP_LOGI(TAG, "[%s] Reset timer count: %d", __func__, reset_cnt);

        if(reset_cnt >= FW_RESET_TIME){
            ledc_set_duty(ledc_channel.speed_mode, ledc_channel.channel, (1 << 20) - 1);
            ledc_update_duty(ledc_channel.speed_mode, ledc_channel.channel);

            do_reset = true;
        }
    }

    return do_reset;
}

void app_main()
{
    EventBits_t events;
    bool exit, fw_reset;
    esp_err_t result;

    fw_reset = false;

    if(restart_marker.magic != HEPH_MAGIC){
        ESP_LOGE(TAG, "[%s] Initialising restart marker", __func__);
        restart_marker.magic = HEPH_MAGIC;
        restart_marker.count = 0;
    } else {
        ESP_LOGE(TAG, "[%s] Found restart marker. Count: %d", __func__, restart_marker.count);
        ++restart_marker.count;
    }

    result = setup_gpios();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "GPIO init failed");
        goto err_out;
    }


    result = nvs_flash_init();
    if(result == ESP_ERR_NVS_NO_FREE_PAGES){
        nvs_flash_erase();
        result = nvs_flash_init();
    }

    if(result != ESP_OK){
        ESP_LOGE(TAG, "NVS init failed");
        goto err_out;
    }

    wifi_cfg_lock = xSemaphoreCreateMutex();
    if(wifi_cfg_lock == NULL){
        ESP_LOGE(TAG, "Creating wifi_cfg_lock failed.");
        goto err_out;
    }

    heph_event_group = xEventGroupCreate();
    if(heph_event_group == NULL){
        ESP_LOGE(TAG, "Creating heph_event_group failed");
        goto err_out;
    }

    init_wifi();

    /* put WiFi into setup-mode if there is no configuration in NVS */
    result = heph_get_cfg(&wifi_cfg, cfg_nvs);
    if(result != ESP_OK){
        ESP_LOGI(TAG, "No config in NVS, entering setup mode");

        memset(&wifi_cfg, 0x0, sizeof(wifi_cfg));
        strlcpy(wifi_cfg.tz, TIMEZONE, sizeof(wifi_cfg.tz));
        setenv("TZ", wifi_cfg.tz, 1);
        tzset();

        init_wifi_cfg(&wifi_cfg, &heph_state);

        result = config_wifi(&heph_state);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "Entering setup mode failed");
        }
    }

    xTaskCreate(&avm_aha_task, "avm_aha_task", 8192, NULL, 5, NULL);

    heph_timer =
        xTimerCreate("HEPH_Timer", pdMS_TO_TICKS(5000), pdTRUE, NULL, timer_cb);

    if(heph_timer == NULL){
        ESP_LOGE(TAG, "Creating heph_timer failed.");
        goto err_out;
    }

    result = xTimerStart(heph_timer, portMAX_DELAY);
    if(result == pdFAIL){
        ESP_LOGE(TAG, "Starting heph_timer failed.");
        goto err_out;
    }

    fwrst_timer =
        xTimerCreate("FWRST_Timer", pdMS_TO_TICKS(2000), pdTRUE, NULL, timer_cb);

    if(fwrst_timer == NULL){
        ESP_LOGE(TAG, "Creating fwrst_timer failed.");
        goto err_out;
    }

    http_srv_init();

    xEventGroupSetBits(heph_event_group, (BIT_TRIGGER | BIT_RELOAD_CFG));

    exit = false;
    while(!exit && !fw_reset){
        events = xEventGroupWaitBits(heph_event_group, BIT_TRIGGER,
                                     true, false, portMAX_DELAY);

        if(events & BIT_RELOAD_CFG){
            ESP_LOGI(TAG, "Reloading config");
            xEventGroupClearBits(heph_event_group, BIT_RELOAD_CFG);
            result = reload_cfg();
            if(result != ESP_OK){
                xEventGroupSetBits(heph_event_group, BIT_RELOAD_CFG);
            }
        }

        fw_reset = check_fwreset();

        update_sntp();

        if(!(events & BIT_AHA_CFG)){
            check_aha_cfg();
        }

        if((events & (BIT_NTP_SYNC | BIT_AHA_CFG))
                == (BIT_NTP_SYNC | BIT_AHA_CFG))
        {
            if(!(events & BIT_AHA_RUN)){
                aha_task_resume();
                xEventGroupSetBits(heph_event_group, BIT_AHA_RUN);
            }
        } else {
            if(events & BIT_AHA_RUN){
                aha_task_suspend();
                xEventGroupClearBits(heph_event_group, BIT_AHA_RUN);
            }
        }

        /* If we get here, the firmware seems to be somewhat stable. Clear
         * the incomplete start marker so we will not fall back to factory
         * image. */
        restart_marker.count = 0;
    }

    if(fw_reset){
        /* Wait for user to release button. Otherwise bootloader will enter
         * download mode on reset.   */
        while(gpio_get_level(GPIO_FW_RESET) == 0)
            ;

        //nvs_flash_erase();
        software_reset();
    }

err_out:
    ESP_LOGE(TAG, "Enter error state");
    while(1)
        ;
}
