#include <string.h>
#include <stdatomic.h>
#include <errno.h>

#include <freertos/FreeRTOS.h>
#include <freertos/timers.h>
#include <freertos/event_groups.h>

#include <esp_event_loop.h>
#include <esp_wifi_types.h>
#include <esp_wifi.h>
#include <esp_wps.h>
#include <esp_log.h>
#include <esp_err.h>

#include <wifi_manager.h>
#include <kref.h>

static const char *TAG = "wifimngr";

#define MAX_NUM_APS     32
#define SCAN_TIMEOUT    (60 * 1000 / portTICK_PERIOD_MS)
#define CFG_TIMEOUT     (60 * 1000 / portTICK_PERIOD_MS)
#define CFG_TICKS       (1000 / portTICK_PERIOD_MS)
#define CFG_DELAY       (100 / portTICK_PERIOD_MS)

/* Jiffy overflow handling stolen from Linux kernel. Needed to check *\
\* for timeouts.                                                     */
#define typecheck(type,x) \
({  type __dummy; \
    typeof(x) __dummy2; \
    (void)(&__dummy == &__dummy2); \
    1; \
})

#define time_after(a,b)     \
        (typecheck(unsigned int, a) && \
         typecheck(unsigned int, b) && \
         ((long)((b) - (a)) < 0))

/* States used during WiFi (re)configuration. */
enum cfg_state {
    /* "stable" states */
    cfg_state_failed,
    cfg_state_connected,
    cfg_state_idle,

    /* transitional states */
    cfg_state_update,
    cfg_state_wps_start,
    cfg_state_wps_active,
    cfg_state_connecting,
    cfg_state_disconnecting,
    cfg_state_fallback,
};

const char *state_names[] = {
        "Failed",
        "Connected",
        "Idle",
        "Update",
        "WPS Start",
        "WPS Active",
        "Connecting",
        "Fall Back"
};

/* This holds all the information needed to transition from the current  *\
 * to the requested WiFi configuration. See handle_config_timer() and    *
\* update_wifi() on how to use this.                                     */
struct wifi_cfg_state {
    SemaphoreHandle_t lock;
    TickType_t timestamp;
    enum cfg_state state;
    struct wifi_cfg saved;
    struct wifi_cfg new;
};

static struct wifi_cfg_state cfg_state;

/* For keeping track of system events. */
#define BIT_CONNECTED       BIT0
#define BIT_GOT_IP          BIT1
#define BIT_DISCONNECTED    BIT2
#define BIT_SCAN_DONE       BIT3
#define BIT_WPS_SUCCESS     BIT4
#define BIT_WPS_FAILED      BIT5
#define BITS_WPS    (BIT_WPS_SUCCESS | BIT_WPS_FAILED)

static EventGroupHandle_t wifi_events = NULL;

struct scan_data_ref {
    struct kref ref_cnt;
    struct scan_data data;
};

struct ap_data_iter{
    struct scan_data *data;
    uint16_t idx;
};


static volatile atomic_bool scan_in_progress = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t data_lock = NULL;
static struct scan_data_ref *last_scan = NULL;
static TimerHandle_t *scan_timer = NULL;
static TimerHandle_t *config_timer = NULL;

static void handle_scan_timer(TimerHandle_t timer);
static void handle_config_timer(TimerHandle_t timer);

/* Initialise data structures. Needs to be called before any other function, *\
\* including the system event handler.                                       */
esp_err_t esp_wmngr_init(void)
{
    esp_err_t result;

    configASSERT(wifi_events == NULL);
    configASSERT(data_lock == NULL);
    configASSERT(cfg_state.lock == NULL);
    configASSERT(scan_timer == NULL);
    configASSERT(config_timer == NULL);

    result = ESP_OK;
    memset(&cfg_state, 0x0, sizeof(cfg_state));
    cfg_state.state = cfg_state_idle;

    wifi_events = xEventGroupCreate();
    if(wifi_events == NULL){
        ESP_LOGE(TAG, "Unable to create event group.");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    data_lock = xSemaphoreCreateMutex();
    if(data_lock == NULL){
        ESP_LOGE(TAG, "Unable to create scan data lock.");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    cfg_state.lock = xSemaphoreCreateMutex();
    if(cfg_state.lock == NULL){
        ESP_LOGE(TAG, "Unable to create state lock.");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    scan_timer = xTimerCreate("Scan_Timer",
                              SCAN_TIMEOUT,
                              pdFALSE, NULL, handle_scan_timer);
    if(scan_timer == NULL){
        ESP_LOGE(TAG, "[%s] Failed to create scan timeout timer",
                 __FUNCTION__);
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    config_timer = xTimerCreate("Config_Timer",
                              CFG_TICKS,
                              pdFALSE, NULL, handle_config_timer);
    if(config_timer == NULL){
        ESP_LOGE(TAG, "[%s] Failed to create config validation timer",
                 __FUNCTION__);
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

err_out:
    if(result != ESP_OK){
        if(wifi_events != NULL){
            vEventGroupDelete(wifi_events);
            wifi_events = NULL;
        }

        if(data_lock != NULL){
            vSemaphoreDelete(data_lock);
            data_lock = NULL;
        }

        if(cfg_state.lock != NULL){
            vSemaphoreDelete(cfg_state.lock);
            cfg_state.lock = NULL;
        }

        if(scan_timer != NULL){
            xTimerDelete(scan_timer, 0);
            scan_timer = NULL;
        }

        if(config_timer != NULL){
            xTimerDelete(config_timer, 0);
            config_timer = NULL;
        }
    }

    return result;
}

/* Get a reference counted pointer to the current set of AP scan data. *\
\* Must be released via put_scan_data().                               */
struct scan_data *esp_wmngr_get_scan(void)
{
    struct scan_data *data;

    configASSERT(data_lock != NULL);

    data = NULL;
    if(data_lock == NULL || last_scan == NULL){
        goto err_out;
    }

    if(xSemaphoreTake(data_lock, CFG_DELAY) == pdTRUE){
        data = &(last_scan->data);
        kref_get(&(last_scan->ref_cnt));
        xSemaphoreGive(data_lock);
    }

err_out:
    return data;
}

/* Free scan data, should only be called kref_put(). */
static void free_scan_data(struct kref *ref)
{
    struct scan_data_ref *data;

    data = kcontainer_of(ref, struct scan_data_ref, ref_cnt);
    free(data->data.ap_records);
    free(data);
}

/* Drop a reference to a scan data set, possibly freeing it. */
void esp_wmngr_put_scan(struct scan_data *data)
{
    struct scan_data_ref *data_ref;

    configASSERT(data != NULL);

    data_ref = kcontainer_of(data, struct scan_data_ref, data);
    kref_put(&(data_ref->ref_cnt), free_scan_data);
}

/* Fetch the latest AP scan data and make it available. */
static void wifi_scan_done(system_event_t *event)
{
    uint16_t num_aps;
    struct scan_data_ref *old, *new;
    esp_err_t result;

    result = ESP_OK;
    new = NULL;

    /* cgiWifiSetup() must have been called prior to this point. */
    configASSERT(data_lock != NULL);

    /* Receiving anything other than scan done means something is *\
    \* really messed up.                                          */
    configASSERT(event->event_id == SYSTEM_EVENT_SCAN_DONE);

    if(atomic_load(&scan_in_progress) == false){
        /* Either scan was cancelled due to timeout or somebody else *\
        \* is triggering scans.                                      */
        ESP_LOGE(TAG, "[%s] Received unsolicited scan done event.",
                 __FUNCTION__);
        return;
    }

    if(event->event_info.scan_done.status != ESP_OK){
        ESP_LOGI(TAG, "Scan failed. Event status: 0x%x",
                 event->event_info.scan_done.status);
        goto err_out;
    }

    /* Fetch number of APs found. Bail out early if there is nothing to get. */
    result = esp_wifi_scan_get_ap_num(&num_aps);
    if(result != ESP_OK || num_aps == 0){
        ESP_LOGI(TAG, "Scan error or empty scan result");
        goto err_out;
    }

    /* Limit number of records to fetch. Prevents possible DoS by tricking   *\
    \* us into allocating storage for a very large amount of scan results.   */
    if(num_aps > MAX_NUM_APS){
        ESP_LOGI(TAG, "Limiting AP records to %d (Actually found %d)",
                 MAX_NUM_APS, num_aps);
        num_aps = MAX_NUM_APS;
    }

    /* Allocate and initialise memory for scan data and AP records. */
    new = calloc(1, sizeof(*new));
    if(new == NULL){
        ESP_LOGE(TAG, "Out of memory creating scan data");
        goto err_out;
    }

    kref_init(&(new->ref_cnt)); // initialises ref_cnt to 1
    new->data.ap_records = calloc(num_aps, sizeof(*(new->data.ap_records)));
    if(new->data.ap_records == NULL){
        ESP_LOGE(TAG, "Out of memory for fetching records");
        goto err_out;
    }

    /* Fetch actual AP scan data */
    new->data.num_records = num_aps;
    result = esp_wifi_scan_get_ap_records(&(new->data.num_records),
                                          new->data.ap_records);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "Error getting scan results");
        goto err_out;
    }

    ESP_LOGI(TAG, "Scan done: found %d APs", num_aps);

    /* Make new scan data available. */
    if(xSemaphoreTake(data_lock, portTICK_PERIOD_MS) == pdTRUE){
        /* The new data set will be assigned to the global pointer, so fetch *\
        \* another reference.                                                */
        kref_get(&(new->ref_cnt));

        old = last_scan;
        last_scan = new;

        if(old != NULL){
            /* Drop global reference to old data set so it will be freed    *\
            \* when the last connection using it gets closed.               */
            esp_wmngr_put_scan(&(old->data));
        }

        xSemaphoreGive(data_lock);
    }

err_out:
    /* Drop one reference to the new scan data. */
    if(new != NULL){
        esp_wmngr_put_scan(&(new->data));
    }

    /* Clear scan flag so a new scan can be triggered. */
    atomic_store(&scan_in_progress, false);
    if(scan_timer != NULL){
        xTimerStop(scan_timer, 0);
    }
}

/* Timer function to stop a hanging AP scan. */
static void handle_scan_timer(TimerHandle_t timer)
{
    atomic_bool tmp = ATOMIC_VAR_INIT(true);

    if(atomic_compare_exchange_strong(&scan_in_progress, &tmp, true) == true){
        ESP_LOGI(TAG, "[%s] Timeout, stopping scan.", __FUNCTION__);
        (void) esp_wifi_scan_stop();
        atomic_store(&scan_in_progress, false);
    }
}

/* Function to trigger an AP scan. */
void esp_wmngr_start_scan(void)
{
    wifi_scan_config_t scan_cfg;
    wifi_mode_t mode;
    esp_err_t result;

    /* Make sure we do not try to start a scan while the WiFi config is *\
    \* is in a transitional state.                                      */
    if(xSemaphoreTake(cfg_state.lock, CFG_DELAY) != pdTRUE){
        ESP_LOGW(TAG, "[%s] Unable to acquire config lock.", __FUNCTION__);
        return;
    }

    if(cfg_state.state > cfg_state_idle){
        ESP_LOGI(TAG, "[%s] WiFi connecting, not starting scan.",
                 __FUNCTION__);
        goto err_out;
    }

    /* Check that we are in a suitable mode for scanning. */
    result =  esp_wifi_get_mode(&mode);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        goto err_out;
    }

    if(mode != WIFI_MODE_APSTA && mode != WIFI_MODE_STA){
        ESP_LOGE(TAG, "[%s] Invalid WiFi mode for scanning.", __FUNCTION__);
        goto err_out;
    }

    /* Finally, start a scan. Unless there is one running already. */
    if(atomic_exchange(&scan_in_progress, true) == false){
        ESP_LOGI(TAG, "[%s] Starting scan.", __FUNCTION__);

        memset(&scan_cfg, 0x0, sizeof(scan_cfg));
        scan_cfg.show_hidden = true;
        scan_cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;

        result = esp_wifi_scan_start(&scan_cfg, false);
        if(result == ESP_OK){
            ESP_LOGI(TAG, "[%s] Starting timer.", __FUNCTION__);

            /* Trigger the timer so scan will be aborted after timeout. */
            xTimerReset(scan_timer, 0);
        } else {
            ESP_LOGE(TAG, "[%s] Starting AP scan failed.", __FUNCTION__);

            atomic_store(&scan_in_progress, false);
        }
    } else {
        ESP_LOGI(TAG, "[%s] Scan aleady running.", __FUNCTION__);
    }

err_out:
    xSemaphoreGive(cfg_state.lock);
    return;
}

/* Helper function to check if WiFi is connected in station mode. */
static bool sta_connected(void)
{
    EventBits_t events;

    events = xEventGroupGetBits(wifi_events);

    return !!(events & BIT_CONNECTED);
}

/* Helper function to set WiFi configuration from struct wifi_cfg. */
static void set_wifi_cfg(struct wifi_cfg *cfg)
{
    esp_err_t result;

    /* FIXME: we should check for errors. OTOH, this is also used  *\
     *        for the fall-back mechanism, so aborting on error is *
    \*        probably a bad idea.                                 */
    result = esp_wifi_restore();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_restore(): %d %s",
                 __FUNCTION__, result, esp_err_to_name(result));
    }

    result = esp_wifi_set_mode(cfg->mode);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_set_mode(): %d %s",
                 __FUNCTION__, result, esp_err_to_name(result));
    }

    if(cfg->mode == WIFI_MODE_APSTA || cfg->mode == WIFI_MODE_AP){
        result = esp_wifi_set_config(WIFI_IF_AP, &(cfg->ap));
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_set_config() AP: %d %s",
                     __FUNCTION__, result, esp_err_to_name(result));
        }
    }

    if(cfg->mode == WIFI_MODE_APSTA || cfg->mode == WIFI_MODE_STA){
        result = esp_wifi_set_config(WIFI_IF_STA, &(cfg->sta));
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_set_config() STA: %d %s",
                     __FUNCTION__, result, esp_err_to_name(result));
        }
    }

    result = esp_wifi_start();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_start(): %d %s",
                 __FUNCTION__, result, esp_err_to_name(result));
    }

    if(cfg->connect
       && (   cfg->mode == WIFI_MODE_STA
           || cfg->mode == WIFI_MODE_APSTA))
    {
        result = esp_wifi_connect();
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_connect(): %d %s",
                     __FUNCTION__, result, esp_err_to_name(result));
        }
    }
}

/* Helper to store current WiFi configuration into a struct wifi_cfg. */
static esp_err_t get_wifi_cfg(struct wifi_cfg *cfg)
{
    esp_err_t result;

    result = ESP_OK;
    memset(cfg, 0x0, sizeof(*cfg));

    cfg->connect = sta_connected();

    result = esp_wifi_get_config(WIFI_IF_STA, &(cfg->sta));
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching STA config.", __FUNCTION__);
        goto err_out;
    }

    result = esp_wifi_get_config(WIFI_IF_AP, &(cfg->ap));
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
        goto err_out;
    }

    result = esp_wifi_get_mode(&(cfg->mode));
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        goto err_out;
    }

err_out:
    return result;
}


/* This function is called from the config_timer and handles all WiFi        *\
 * configuration changes. It takes its information from the global           *
 * cfg_state struct and tries to set the WiFi configuration to the one       *
 * found in the "new" member. If things go wrong, it will try to fall        *
 * back to the configuration found in "saved". This should minimise          *
 * the risk of users locking themselves out of the device by setting         *
 * wrong WiFi credentials in STA-only mode.                                  *
 *                                                                           *
 * This function will keep triggering itself until it reaches a "stable"     *
 * (idle, connected, failed) state in cfg_state.state.                       *
 *                                                                           *
 * cfg_state must not be modified without first obtaining the cfg_state.lock *
 * mutex and then checking that cfg_state.state is in a stable state.        *
 * To set a new configuration, just store the current config to .saved,      *
 * update .new to the desired config, set .state to cfg_state_update         *
 * and start the config_timer.                                               *
 * To connect to an AP with WPS, save the current state, set .state          *
 * to cfg_state_wps_start and start the config_timer.                        *
 \*                                                                          */
static void handle_config_timer(TimerHandle_t timer)
{
    bool connected;
    wifi_mode_t mode;
    esp_wps_config_t config = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PBC);
    TickType_t now, delay;
    EventBits_t events;
    esp_err_t result;

    /* If we can not get the config state lock, we try to reschedule the    *\
     * timer. If that also fails, we are SOL...                             *
    \* Maybe we should trigger a reboot.                                    */
    if(xSemaphoreTake(cfg_state.lock, 0) != pdTRUE){
        if(xTimerChangePeriod(config_timer, CFG_DELAY, CFG_DELAY) != pdPASS){
            ESP_LOGE(TAG, "[%s] Failure to get config lock and change timer.",
                     __FUNCTION__);
        }
        return;
    }

    ESP_LOGD(TAG, "[%s] Called. State: %s",
             __FUNCTION__, state_names[cfg_state.state]);

    /* If delay gets set later, the timer will be re-scheduled on exit. */
    delay = 0;

    /* Gather various information about the current system state. */
    connected = sta_connected();
    events = xEventGroupGetBits(wifi_events);
    now = xTaskGetTickCount();

    result = esp_wifi_get_mode(&mode);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        cfg_state.state = cfg_state_failed;
        goto err_out;
    }

    switch(cfg_state.state){
    case cfg_state_wps_start:

        /* Try connecting to AP with WPS. First, tear down any connection *\
        \* we might currently have.                                       */
        get_wifi_cfg(&cfg_state.new);
        memset(&cfg_state.new.sta, 0x0, sizeof(cfg_state.new.sta));
        cfg_state.new.mode = WIFI_MODE_APSTA;
        cfg_state.new.connect = false;

        set_wifi_cfg(&cfg_state.new);

        /* Clear previous results and start WPS. */
        xEventGroupClearBits(wifi_events, BITS_WPS);
        result = esp_wifi_wps_enable(&config);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_wps_enable() failed: %d %s",
                     __FUNCTION__, result, esp_err_to_name(result));
            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        }

        result = esp_wifi_wps_start(0);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] esp_wifi_wps_start() failed: %d %s",
                     __FUNCTION__, result, esp_err_to_name(result));
            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        }

        /* WPS is running, set time stamp and transition to next state. */
        cfg_state.timestamp = now;
        cfg_state.state = cfg_state_wps_active;
        delay = CFG_TICKS;
        break;
    case cfg_state_wps_active:
        /* WPS is running. Check for events and timeout. */
        if(events & BIT_WPS_SUCCESS){
            /* WPS succeeded. Disable WPS and use the received credentials *\
             * to connect to the AP by transitioning to the updating state.*/
            ESP_LOGI(TAG, "[%s] WPS success.", __FUNCTION__);
            result = esp_wifi_wps_disable();
            if(result != ESP_OK){
                ESP_LOGE(TAG, "[%s] wifi wps disable: %d %s",
                        __FUNCTION__, result, esp_err_to_name(result));
            }

            /* Get received STA config, then force APSTA mode, set  *\
            \* connect flag and trigger update.                     */
            get_wifi_cfg(&cfg_state.new);
            cfg_state.new.mode = WIFI_MODE_APSTA;
            cfg_state.new.connect = true;
            cfg_state.state = cfg_state_update;
            delay = CFG_DELAY;
        } else if(   time_after(now, (cfg_state.timestamp + CFG_TIMEOUT))
                  || (events & BIT_WPS_FAILED))
        {
            /* Failure or timeout. Trigger fall-back to the previous config. */
            ESP_LOGI(TAG, "[%s] WPS failed, restoring saved config.",
                     __FUNCTION__);

            result = esp_wifi_wps_disable();
            if(result != ESP_OK){
                ESP_LOGE(TAG, "[%s] wifi wps disable: %d %s",
                        __FUNCTION__, result, esp_err_to_name(result));
            }

            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        } else {
            delay = CFG_TICKS;
        }
        break;
    case cfg_state_update:
        /* Start changing WiFi to new configuration. */
        (void) esp_wifi_scan_stop();
        (void) esp_wifi_disconnect();
        set_wifi_cfg(&(cfg_state.new));

        if(cfg_state.new.mode == WIFI_MODE_AP || !cfg_state.new.connect){
            /* AP-only mode or not connecting, we are done. */
            cfg_state.state = cfg_state_idle;
        } else {
            /* System should now connect to the AP. */
            cfg_state.timestamp = now;
            cfg_state.state = cfg_state_connecting;
            delay = CFG_TICKS;
        }
        break;
    case cfg_state_connecting:
        /* We are waiting for a connection to an AP. */
        if(connected){
            /* We have a connection! \o/ */
            cfg_state.state = cfg_state_connected;
        } else if(time_after(now, (cfg_state.timestamp + CFG_TIMEOUT))){
            /* Timeout while waiting for connection. Try falling back to the *\
            \* saved configuration.                                          */
            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        } else {
            /* Twiddle our thumbs and keep waiting for the connection.  */
            delay = CFG_TICKS;
        }
        break;
    case cfg_state_disconnecting:
        break;
    case cfg_state_fallback:
        /* Something went wrong, try going back to the previous config. */
        (void) esp_wifi_disconnect();
        set_wifi_cfg(&(cfg_state.saved));
        cfg_state.state = cfg_state_failed;
        break;
    case cfg_state_idle:
    case cfg_state_connected:
    case cfg_state_failed:
        break;
    }

err_out:
    if(delay > 0){
        /* We are in a transitional state, re-arm the timer. */
        if(xTimerChangePeriod(config_timer, delay, CFG_DELAY) != pdPASS){
            cfg_state.state = cfg_state_failed;
        }
    }

    ESP_LOGD(TAG, "[%s] Leaving. State: %s delay: %d",
             __FUNCTION__, state_names[cfg_state.state], delay);

    xSemaphoreGive(cfg_state.lock);
    return;
}

static const char *event_names[] = {
        "WIFI_READY",
        "SCAN_DONE",
        "STA_START",
        "STA_STOP",
        "STA_CONNECTED",
        "STA_DISCONNECTED",
        "STA_AUTHMODE_CHANGE",
        "STA_GOT_IP",
        "STA_LOST_IP",
        "STA_WPS_ER_SUCCESS",
        "STA_WPS_ER_FAILED",
        "STA_WPS_ER_TIMEOUT",
        "STA_WPS_ER_PIN",
        "AP_START",
        "AP_STOP",
        "AP_STACONNECTED",
        "AP_STADISCONNECTED",
        "AP_STAIPASSIGNED",
        "AP_PROBEREQRECVED",
        "GOT_IP6",
        "ETH_START",
        "ETH_STOP",
        "ETH_CONNECTED",
        "ETH_DISCONNECTED",
        "ETH_GOT_IP",
};

/* Update state information from system events. This function must be   *\
 * called from the main event handler to keep this module updated about *
\* the current system state.                                            */
esp_err_t esp_wmngr_event_handler(void *ctx, system_event_t *event)
{
    ESP_LOGD(TAG, "[%s] Received %s.",
            __FUNCTION__, event_names[event->event_id]);

    switch(event->event_id){
    case SYSTEM_EVENT_SCAN_DONE:
        wifi_scan_done(event);
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
    case SYSTEM_EVENT_GOT_IP6:
        xEventGroupSetBits(wifi_events, BIT_CONNECTED);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        xEventGroupClearBits(wifi_events, BIT_CONNECTED);
        break;
    case SYSTEM_EVENT_STA_WPS_ER_SUCCESS:
        xEventGroupSetBits(wifi_events, BIT_WPS_SUCCESS);
        break;
    case SYSTEM_EVENT_STA_WPS_ER_FAILED:
    case SYSTEM_EVENT_STA_WPS_ER_TIMEOUT:
    case SYSTEM_EVENT_STA_WPS_ER_PIN:
        xEventGroupSetBits(wifi_events, BIT_WPS_FAILED);
        break;
    default:
        break;
    }

    return ESP_OK;
}

/* Set a new WiFi configuration. This function will save the current config *\
 * to cfg->saved, then compare it to the requested new configuration. If    *
 * the two configurations are different, it will store the new config in    *
\* cfg->new and trigger the asynchronous mechanism to handle the update.    */
esp_err_t esp_wmngr_update(struct wifi_cfg *new)
{
    bool connected;
    bool update;
    esp_err_t result;

    if(xSemaphoreTake(cfg_state.lock, CFG_DELAY) != pdTRUE){
        ESP_LOGE(TAG, "[%s] Error taking mutex.", __FUNCTION__);
        return ESP_ERR_TIMEOUT;
    }

    if(cfg_state.state > cfg_state_idle){
        ESP_LOGI(TAG, "[%s] WiFi change in progress.", __FUNCTION__);
        result = ESP_ERR_INVALID_STATE;
        goto err_out;
    }

    result = ESP_OK;

    /* Save current configuration for fall-back. */
    result = get_wifi_cfg(&(cfg_state.saved));
    if(result != ESP_OK){
        ESP_LOGI(TAG, "[%s] Error fetching current WiFi config.",
                 __FUNCTION__);
        goto err_out;
    }

    /* Clear station configuration if we are not connected to an AP. */
    connected = sta_connected();
    if(!connected){
        memset(&(cfg_state.saved.sta), 0x0, sizeof(cfg_state.saved.sta));
    }

    memmove(&(cfg_state.new), new, sizeof(cfg_state.new));
    update = false;

    /* Do some naive checks to see if the new configuration is an actual   *\
    \* change. Should be more thorough by actually comparing the elements. */
    if(cfg_state.new.mode != cfg_state.saved.mode){
        update = true;
    }

    if((new->mode == WIFI_MODE_AP || new->mode == WIFI_MODE_APSTA)
       && memcmp(&(cfg_state.new.ap), &(cfg_state.saved.ap), sizeof(cfg_state.new.ap)))
    {
        update = true;
    }

    if((new->mode == WIFI_MODE_STA || new->mode == WIFI_MODE_APSTA)
       && memcmp(&(cfg_state.new.sta), &(cfg_state.saved.sta), sizeof(cfg_state.new.sta)))
    {
        update = true;
    }

    /* If new config is different, trigger asynchronous update. This gives *\
     * the httpd some time to send out the reply before possibly tearing   *
    \* down the connection.                                                */
    if(update == true){
        cfg_state.state = cfg_state_update;
        if(xTimerChangePeriod(config_timer, CFG_DELAY, CFG_DELAY) != pdPASS){
            cfg_state.state = cfg_state_failed;
            result = ESP_ERR_TIMEOUT;
            goto err_out;
        }
    }

err_out:
    xSemaphoreGive(cfg_state.lock);
    return result;
}

/* CGI for triggering a WPS push button connection attempt. */
esp_err_t esp_wmngr_start_wps(void)
{
    struct wifi_cfg cfg;
    esp_err_t result;

    result = ESP_OK;

    /* Make sure we are not in the middle of setting a new WiFi config. */
    if(xSemaphoreTake(cfg_state.lock, CFG_DELAY) != pdTRUE){
        ESP_LOGE(TAG, "[%s] Error taking mutex.", __FUNCTION__);
        return ESP_ERR_TIMEOUT;
    }

    if(cfg_state.state > cfg_state_idle){
        ESP_LOGI(TAG, "[%s] WiFi change in progress.", __FUNCTION__);
        result = ESP_ERR_INVALID_STATE;
        goto err_out;
    }

    ESP_LOGI(TAG, "[%s] Starting WPS.", __FUNCTION__);

    /* Save current config for fall-back. */
    result = get_wifi_cfg(&cfg);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] Error fetching WiFi config.", __FUNCTION__);
        goto err_out;
    }

    memmove(&cfg_state.saved, &cfg, sizeof(cfg_state.saved));
    cfg_state.state = cfg_state_wps_start;

    if(xTimerChangePeriod(config_timer,CFG_DELAY,CFG_DELAY) != pdTRUE){
        cfg_state.state = cfg_state_failed;
    }

err_out:
    xSemaphoreGive(cfg_state.lock);
    return result;
}
