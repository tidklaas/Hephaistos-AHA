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
#include <esp_wps.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <driver/gpio.h>
#include <driver/ledc.h>
#include <esp_intr_alloc.h>
#include <esp32/rom/rtc.h>
#include <esp_ota_ops.h>
#include <esp_image_format.h>
#include <esp_sntp.h>

#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <lwip/dns.h>

#include <wifi_manager.h>
#include <libesphttpd/cgiwifi.h>
#include <http_srv.h>

#define TIMEZONE        CONFIG_TIMEZONE
#define GPIO_HEAT       CONFIG_GPIO_HEAT
#define GPIO_LED        CONFIG_GPIO_LED
#define GPIO_FW_RESET   CONFIG_GPIO_FW_RESET

#define TWDT_TIMEOUT_S          300
#define TASK_RESET_PERIOD_S     5
#define FW_RESET_TIME           10

static struct heph_cfg heph_cfg;
static char sntp_srv[64];

static SemaphoreHandle_t cfg_lock = NULL;

static EventGroupHandle_t heph_event_group;
static TimerHandle_t heph_timer = NULL;
static TimerHandle_t fwrst_timer = NULL;

#define HEPH_MAGIC  0x48455048  /* "HEPH" */

__NOINIT_ATTR static volatile struct _restart_marker {
    uint32_t magic;
    uint32_t count;
} restart_marker;

static const char *TAG = "HEPH";

static const int BIT_TRIGGER       = BIT0;
static const int BIT_RELOAD_CFG    = BIT1;
static const int BIT_NTP_SYNC      = BIT2;
static const int BIT_AHA_CFG       = BIT3;
static const int BIT_AHA_RUN       = BIT4;
static const int BIT_FW_RESET      = BIT5;

static void update_sntp_cb(struct timeval *tv)
{
    char buff[64];
    struct tm tm;

    memset(&tm, 0x0, sizeof(tm));
    localtime_r(&(tv->tv_sec), &tm);

    if(tm.tm_year > (2016 - 1900)){
        ESP_LOGI(TAG, "[%s] Got NTP time sync: %s",
                __func__, asctime_r(&tm, buff));

        xEventGroupSetBits(heph_event_group, BIT_NTP_SYNC);
    }
}

static void update_sntp(void)
{
    bool connected, running, cfg_changed;
    struct aha_cfg aha_cfg;
    esp_err_t result;

    cfg_changed = false;
    result = aha_get_cfg(&aha_cfg, cfg_ram);
    if(result == ESP_ERR_TIMEOUT){
        /* Temporary error, return immediately. */
        goto on_exit;
    }

    if(result != ESP_OK
       || strncmp(sntp_srv, aha_cfg.fbox_addr, sizeof(aha_cfg.fbox_addr)))
    {
        cfg_changed = true;
    }

    connected = esp_wmngr_is_connected();
    running = sntp_enabled();

    if(running){
        if(!connected || cfg_changed){
            ESP_LOGI(TAG, "Stopping SNTP");
            sntp_stop();
            memset(sntp_srv, 0x0, sizeof(sntp_srv));
            xEventGroupClearBits(heph_event_group, BIT_NTP_SYNC);
            running = false;
        }
    }

    if(connected && !running){
        if(strnlen(aha_cfg.fbox_addr, sizeof(aha_cfg.fbox_addr)) == 0){
            ESP_LOGD(TAG, "[%s] fbox_addr empty", __func__);
            goto on_exit;
        }

        ESP_LOGI(TAG, "Starting SNTP");
        ESP_LOGI(TAG, "SNTP-Server: %s", aha_cfg.fbox_addr);
        strlcpy(sntp_srv, aha_cfg.fbox_addr, sizeof(sntp_srv));
        sntp_set_time_sync_notification_cb(update_sntp_cb);
        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, sntp_srv);
        sntp_init();
    }

on_exit:
    return;
}

esp_err_t heph_set_cfg(struct heph_cfg *cfg, bool reload)
{
    esp_err_t result;
    nvs_handle handle;

    if(cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    result = nvs_open(HEPH_NVS_NAMESPC, NVS_READWRITE, &handle);
    if(result != ESP_OK){
        return result;
    }

    if(xSemaphoreTake(cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto on_exit;
    }

    /* Timezone is optional */
    if(strlen(cfg->tz) > 0){
        result = nvs_set_str(handle, "timezone", cfg->tz);
        if(result != ESP_OK){
            goto on_exit_unlock;
        }
    }

    result = nvs_commit(handle);
    if(result != ESP_OK){
        goto on_exit_unlock;
    }

    if(reload){
        xEventGroupSetBits(heph_event_group, (BIT_RELOAD_CFG | BIT_TRIGGER));
    }

on_exit_unlock:
    xSemaphoreGive(cfg_lock);

on_exit:
    nvs_close(handle);

    return result;
}

esp_err_t heph_get_cfg(struct heph_cfg *cfg, enum cfg_load_type from)
{
    esp_err_t result;
    size_t len;
    nvs_handle handle;

    if(from != cfg_nvs && from != cfg_ram){
        return ESP_ERR_INVALID_ARG;
    }

    if(cfg_lock == NULL){
        return ESP_ERR_TIMEOUT;
    }

    if(from == cfg_nvs){
        result = nvs_open(HEPH_NVS_NAMESPC, NVS_READONLY, &handle);
        if(result != ESP_OK){
            return result;
        }
    }

    if(xSemaphoreTake(cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto on_exit;
    }

    if(from == cfg_ram){
        memmove(cfg, &heph_cfg, sizeof(*cfg));
        result = ESP_OK;
        goto on_exit_unlock;
    }

    memset(cfg, 0x0, sizeof(*cfg));

    /* Try to read timezone. Fall back to default if not set */
    len = sizeof(cfg->tz);
    result = nvs_get_str(handle, "timezone", cfg->tz, &len);
    if((result != ESP_OK) || (strlen(cfg->tz) == 0)){
        strlcpy(cfg->tz, TIMEZONE, sizeof(cfg->tz));
        result = ESP_OK;
    }

on_exit_unlock:
    xSemaphoreGive(cfg_lock);

on_exit:
    if(from == cfg_nvs){
        nvs_close(handle);
    }

    return result;
}

static esp_err_t reload_cfg(void)
{
    esp_err_t result;
    struct heph_cfg cfg;

    result = heph_get_cfg(&cfg, cfg_nvs);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] heph_get_cfg() failed", __func__);
        goto on_exit;
    }

    if(xSemaphoreTake(cfg_lock, 100 * portTICK_PERIOD_MS) != pdTRUE){
        result = ESP_ERR_TIMEOUT;
        goto on_exit;
    }

    memmove(&heph_cfg, &cfg, sizeof(heph_cfg));

    xSemaphoreGive(cfg_lock);

    if(strlen(heph_cfg.tz) > 0){
        ESP_LOGI(TAG, "[%s] Setting TZ to %s", __func__, heph_cfg.tz);
        setenv("TZ", heph_cfg.tz, 1);
        tzset();
    }

on_exit:
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
    struct aha_cfg cfg;
    esp_err_t result;

    ESP_LOGI(TAG, "Fetching AHA config.");

    result = aha_get_cfg(&cfg, cfg_nvs);
    if(result == ESP_OK){
        xEventGroupSetBits(heph_event_group, BIT_AHA_CFG);
    } else {
        xEventGroupClearBits(heph_event_group, BIT_AHA_CFG);
    }

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
        goto on_exit;
    }

    result = gpio_isr_handler_add(GPIO_FW_RESET, gpio_isr_handler,
                                  (void*) GPIO_FW_RESET);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] gpio_isr_handler_add() failed", __func__);
        goto on_exit;
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
        goto on_exit;
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
        goto on_exit;
    }

on_exit:
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

/** \brief Handle user factory reset request.
 *
 * Check if user pressed button for FW_RESET_TIME seconds. Give visual
 * feedback via the info LED.
 *
 * \returns true if factory reset should be performwed, false otherwise
 */
static bool check_fwreset(void)
{
    EventBits_t events;
    BaseType_t timer_running;
    ledc_timer_config_t ledc_timer;
    ledc_channel_config_t ledc_channel;
    ledc_channel_t chan;
    ledc_mode_t mode;
    bool do_reset;
    static unsigned int reset_cnt = 0;

    do_reset = false;
    events = xEventGroupClearBits(heph_event_group, BIT_FW_RESET);
    timer_running = xTimerIsTimerActive(fwrst_timer);

    if(gpio_get_level(GPIO_FW_RESET) == 0){
        /*
         * Button is (still) pressed. If reset timer is not already running,
         * start it and initialise the reset counter. Also configure the LED
         * GPIO to blink rapidly.
         */
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

        /*
         * Increase the counter if the fw_reset_timer has expired since
         * the last call to this function.
         */
        if((events & BIT_FW_RESET) == BIT_FW_RESET){
            ++reset_cnt;
        }

        ESP_LOGI(TAG, "[%s] Reset timer count: %d", __func__, reset_cnt);

        /*
         * Button has been pressed for at least FW_RESET_TIME seconds.
         * Change LED duty cycle to constant on and set return value
         * to true.
         */
        if(reset_cnt >= FW_RESET_TIME){
            chan = ledc_channel.channel;
            mode = ledc_channel.speed_mode;

            ledc_set_duty(mode, chan, (1 << 20) - 1);
            ledc_update_duty(mode, chan);

            do_reset = true;
        }
    } else {
        /*
         * Button is not pressed. If reset timer is running, stop it and
         * restore LED config to normal function.
         */
        if(timer_running != pdFALSE){
            (void) xTimerStop(fwrst_timer, portMAX_DELAY);
            ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_TIMER_0, 0);
            gpio_matrix_out(GPIO_LED, SIG_GPIO_OUT_IDX, 0, 0);
            ESP_LOGI(TAG, "[%s] Aborting FW reset", __func__);
        }
    }

    return do_reset;
}

void app_main(void)
{
    EventBits_t events;
    bool exit, fw_reset;
    const esp_partition_t *curr_part;
    esp_image_header_t img_hdr;
    esp_err_t result;

    fw_reset = false;

    /*
     * Check firmware startup failsafe. Clear NVS if firmware is boot
     * looping and fall back to previous image.
     */
    if(restart_marker.magic != HEPH_MAGIC){
        ESP_LOGE(TAG, "[%s] Initialising restart marker", __func__);
        restart_marker.magic = HEPH_MAGIC;
        restart_marker.count = 0;
    } else {
        ESP_LOGE(TAG, "[%s] Found restart marker. Count: %d", __func__,
                   restart_marker.count);
        ++restart_marker.count;
        if(restart_marker.count > 10){
            ESP_LOGE(TAG, "Firmware is boot looping, initialising"
                          "fall-back to previous image.");

            /*
             * Invalidate the running image by zeroing out the image's
             * header in the SPI flash. Bootloader should fall back to
             * the last valid image before the OTA.
             */
            curr_part = esp_ota_get_running_partition();

            /* Make sure not to kill the factory image! */
            if(   curr_part != NULL
               && curr_part->type == ESP_PARTITION_TYPE_APP
               && curr_part->subtype != ESP_PARTITION_SUBTYPE_APP_FACTORY)
            {
                memset(&img_hdr, 0x0, sizeof(img_hdr));
                esp_partition_write(curr_part, 0x0, &img_hdr, sizeof(img_hdr));
            }

            /* Clear NVS and reset marker count. */
            nvs_flash_erase();
            restart_marker.count = 0;

            software_reset();
        }
    }

    result = setup_gpios();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "GPIO init failed");
        goto on_exit;
    }

    result = nvs_flash_init();
    if(result == ESP_ERR_NVS_NO_FREE_PAGES){
        nvs_flash_erase();
        result = nvs_flash_init();
    }

    if(result != ESP_OK){
        ESP_LOGE(TAG, "NVS init failed");
        goto on_exit;
    }

    /* Set time zone to compiled-in default. */
    ESP_LOGI(TAG, "[%s] Settin TZ to %s", __func__, TIMEZONE);
    setenv("TZ", TIMEZONE, 1);
    tzset();

    cfg_lock = xSemaphoreCreateMutex();
    if(cfg_lock == NULL){
        ESP_LOGE(TAG, "Creating cfg_lock failed.");
        goto on_exit;
    }

    heph_event_group = xEventGroupCreate();
    if(heph_event_group == NULL){
        ESP_LOGE(TAG, "Creating heph_event_group failed");
        goto on_exit;
    }

    /*
     * Try reading configuration from NVS and set compiled in defaults if it
     * does not exists.
     */
    result = heph_get_cfg(&heph_cfg, cfg_nvs);
    if(result != ESP_OK){
        ESP_LOGI(TAG, "No config in NVS, entering setup mode");

        memset(&heph_cfg, 0x0, sizeof(heph_cfg));
        strlcpy(heph_cfg.tz, TIMEZONE, sizeof(heph_cfg.tz));
        (void) heph_set_cfg(&heph_cfg, true);
    }

    result = esp_event_loop_create_default();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_event_create_default() failed", __func__);
        goto on_exit;
    }

    xTaskCreate(&avm_aha_task, "avm_aha_task", 8192, NULL, 5, NULL);

    heph_timer = xTimerCreate("HEPH_Timer", pdMS_TO_TICKS(5000),
                              pdTRUE, NULL, timer_cb);

    if(heph_timer == NULL){
        ESP_LOGE(TAG, "Creating heph_timer failed.");
        goto on_exit;
    }

    result = xTimerStart(heph_timer, portMAX_DELAY);
    if(result == pdFAIL){
        ESP_LOGE(TAG, "Starting heph_timer failed.");
        goto on_exit;
    }

    fwrst_timer = xTimerCreate("FWRST_Timer", pdMS_TO_TICKS(2000),
                               pdTRUE, NULL, timer_cb);

    if(fwrst_timer == NULL){
        ESP_LOGE(TAG, "Creating fwrst_timer failed.");
        goto on_exit;
    }

    result = esp_wmngr_init();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "esp_wmngr_init() failed.");
        goto on_exit;
    }

    result = esp_wmngr_start();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "esp_wmngr_start() failed.");
        goto on_exit;
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

#if defined(AUTO_WPS)
#warning AUTO_WPS enabled
        /*
         * Trigger WPS if no valid WiFi config is found. Should only be used
         * for development purposes.
         */
        if(!esp_wmngr_nvs_valid()
            && (esp_wmngr_get_state() == wmngr_state_idle))
        {
            result = esp_wmngr_start_wps();
            if(result != ESP_OK){
                ESP_LOGE(TAG, "[%s] start_wps() failed: %s\n",
                        __func__, esp_err_to_name(result));
            }
        }
#endif /* defined(AUTO_WPS) */

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

        /*
         * If we get here, the firmware seems to be somewhat stable. Clear
         * the incomplete start marker so we will not fall back to previous
         * image.
         */
        restart_marker.count = 0;
    }

    if(fw_reset){
        /* Wait for user to release button. Otherwise bootloader will enter
         * download mode on reset.   */
        while(gpio_get_level(GPIO_FW_RESET) == 0)
            ;

        nvs_flash_erase();
        software_reset();
    }

on_exit:

    ESP_LOGE(TAG, "Enter error state");
    /* Try turning of heater. */
    /* TODO: Maybe make data LED flash to signal that there is a problem. */
    heph_heat_set(false);
    while(1)
        ;
}
