#ifndef ESP_WIFI_MANAGER_H
#define ESP_WIFI_MANAGER_H

#include <stdbool.h>
#include "esp_err.h"
#include "esp_wifi_types.h"
#include "esp_event_loop.h"
#include "tcpip_adapter.h"

struct scan_data {
    wifi_ap_record_t *ap_records;
    uint16_t num_records;
};

/* Holds complete WiFi config for both STA and AP, the mode and whether       *\
\* the WiFi should connect to an AP in STA or APSTA mode.                     */
struct wifi_cfg {
    bool connect;
    wifi_mode_t mode;
    wifi_config_t sta;
    wifi_config_t ap;
    bool sta_static;
    tcpip_adapter_ip_info_t static_cfg;
};

esp_err_t esp_wmngr_init(void);
void esp_wmngr_start_scan(void);
struct scan_data *esp_wmngr_get_scan(void);
void esp_wmngr_put_scan(struct scan_data *data);
esp_err_t esp_wmngr_update(struct wifi_cfg *new);
esp_err_t esp_wmngr_event_handler(void *ctx, system_event_t *event);
esp_err_t esp_wmngr_start_wps(void);

#endif // ESP_WIFI_MANAGER_H
