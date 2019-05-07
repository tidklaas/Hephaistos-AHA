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
    wifi_mode_t mode;
    wifi_config_t ap;
    tcpip_adapter_ip_info_t ap_ip_info;
    wifi_config_t sta;
    tcpip_adapter_ip_info_t sta_ip_info;
    tcpip_adapter_dns_info_t sta_dns_info[TCPIP_ADAPTER_DNS_MAX];
    bool sta_static;
    bool sta_connect;
};

esp_err_t esp_wmngr_init(void);
void esp_wmngr_start_scan(void);
struct scan_data *esp_wmngr_get_scan(void);
void esp_wmngr_put_scan(struct scan_data *data);
esp_err_t esp_wmngr_update(struct wifi_cfg *new);
esp_err_t esp_wmngr_event_handler(void *ctx, system_event_t *event);
esp_err_t esp_wmngr_start_wps(void);

#endif // ESP_WIFI_MANAGER_H
