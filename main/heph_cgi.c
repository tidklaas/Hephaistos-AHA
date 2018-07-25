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

static const char *TAG = "CGI";
#define MAX_NUM_APS 16

#define SSID_SIZE	32
#define BSSID_SIZE	6

//WiFi access point data
typedef struct {
    char ssid[SSID_SIZE + 1];
    char bssid[BSSID_SIZE];
    int channel;
    char rssi;
    char enc;
} ApData;

//Scan result
typedef struct {
    char scanInProgress; //if 1, don't access the underlying stuff from the webpage.
    ApData **apData;
    int noAps;
} ScanResultData;

//Static scan status storage.
static ScanResultData cgiWifiAps;

#define CONNTRY_IDLE    0
#define CONNTRY_WORKING 1
#define CONNTRY_SUCCESS 2
#define CONNTRY_FAIL    3

//Connection result var
static int connTryStatus=CONNTRY_IDLE;

// Helper function for releasing collected AP scan data
static void freeApData(void)
{
    unsigned int idx;

    if(cgiWifiAps.apData != NULL){
        for(idx = 0; idx < cgiWifiAps.noAps; ++idx){
            if(cgiWifiAps.apData[idx] != NULL){
                free(cgiWifiAps.apData[idx]);
            }
        }

        free(cgiWifiAps.apData);
    }

    cgiWifiAps.apData = NULL;
    cgiWifiAps.noAps = 0;
}

void wifi_scan_done_cb(void)
{
    uint16_t num_aps;
    wifi_ap_record_t *ap_records;
    ApData *ap_data;
    unsigned int idx;
    esp_err_t result;

    ESP_LOGI(TAG, "wifiScanDoneCb");

    result = ESP_OK;
    ap_records = NULL;

    // Release old data before fetching new set
    freeApData();

    // Fetch number of APs found. Bail out early if there is nothing to get.
    result = esp_wifi_scan_get_ap_num(&num_aps);
    if(result != ESP_OK || num_aps == 0){
        ESP_LOGI(TAG, "Scan error or empty scan result");
        goto err_out;
    }

    // Limit number of records to fetch. Prevents possible DoS by tricking
    // us into allocating storage for a very large amount of scan results.
    if(num_aps > MAX_NUM_APS){
        ESP_LOGI(TAG, "Limiting AP records to %d (Actually found %d)",
                MAX_NUM_APS, num_aps);
        num_aps = MAX_NUM_APS;
    }

    ap_records = malloc(num_aps * sizeof(*ap_records));
    if(ap_records == NULL){
        ESP_LOGE(TAG, "Out of memory for fetching records");
        goto err_out;
    }

    // Fetch actual AP scan data
    result = esp_wifi_scan_get_ap_records(&num_aps, ap_records);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "Error getting scan results");
        goto err_out;
    }

    // Allocate zeroed memory for apData pointer array
    cgiWifiAps.apData = (ApData **) calloc(sizeof(ApData *), num_aps);
    if(cgiWifiAps.apData == NULL){
        ESP_LOGE(TAG, "Out of memory for storing records");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    ESP_LOGI(TAG, "Scan done: found %d APs", num_aps);

    // Allocate and fill apData entries for retrieved scan results
    for(idx = 0; idx < num_aps; ++idx){
        cgiWifiAps.apData[idx] = (ApData *) malloc(sizeof(ApData));
        if(cgiWifiAps.apData[idx] == NULL){
            ESP_LOGE(TAG, "Out of memory while copying AP data");
            result = ESP_ERR_NO_MEM;
            goto err_out;
        }

        ++cgiWifiAps.noAps;

        ap_data = cgiWifiAps.apData[idx];
        ap_data->rssi = ap_records[idx].rssi;
        ap_data->channel = ap_records[idx].primary;
        ap_data->enc = ap_records[idx].authmode;
        strlcpy(ap_data->ssid, (const char *) ap_records[idx].ssid,  sizeof(ap_data->ssid));
        memcpy(ap_data->bssid, ap_records[idx].bssid, sizeof(ap_data->bssid));
    }

err_out:
    // Release scan result buffer
    if(ap_records != NULL){
        free(ap_records);
    }

    // If something went wrong, release possibly incomplete ApData
    if(result != ESP_OK){
        freeApData();
    }

    // Indicate that scan data can now be used
    cgiWifiAps.scanInProgress=0;
}

static esp_err_t wifi_start_scan(void)
{
    esp_err_t result;
    wifi_scan_config_t scan_cfg;

    ESP_LOGI(TAG, "[%s] Called", __func__);

    result = ESP_OK;

    if (cgiWifiAps.scanInProgress){
       goto err_out;
    }

    memset(&scan_cfg, 0x0, sizeof(scan_cfg));
    scan_cfg.show_hidden = true;
    scan_cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;

    result = esp_wifi_scan_start(&scan_cfg, false);
    if(result == ESP_OK){
        cgiWifiAps.scanInProgress=1;
    }

err_out:
    return result;
}

//This CGI is called from the bit of AJAX-code in wifi.tpl. It will initiate a
//scan for access points and if available will return the result of an earlier scan.
//The result is embedded in a bit of JSON parsed by the javascript in wifi.tpl.
CgiStatus cgi_wifi_scan(HttpdConnData *conn)
{
    int pos, len;
    char buff[1024];

    pos=(int)conn->cgiData;

    if (!cgiWifiAps.scanInProgress && pos!=0) {
        //Fill in json code for an access point
        if((pos - 1) < cgiWifiAps.noAps){
            len=sprintf(buff, "{\"essid\": \"%s\", \"bssid\": \"" MACSTR
                              "\", \"rssi\": \"%d\", \"enc\": \"%d\", \"channel\": \"%d\"}%s\n",
                    cgiWifiAps.apData[pos - 1]->ssid, MAC2STR(cgiWifiAps.apData[pos - 1]->bssid),
                    cgiWifiAps.apData[pos - 1]->rssi, cgiWifiAps.apData[pos - 1]->enc,
                    cgiWifiAps.apData[pos - 1]->channel,
                    ((pos - 1) == (cgiWifiAps.noAps - 1)) ? "" : ",");
            httpdSend(conn, buff, len);
        }

        ++pos;

        if((pos - 1) >= cgiWifiAps.noAps){
            len = sprintf(buff, "]\n}\n}\n");
            httpdSend(conn, buff, len);

            //Also start a new scan.
            wifi_start_scan();
            return HTTPD_CGI_DONE;
        } else {
            conn->cgiData = (void*)pos;
            return HTTPD_CGI_MORE;
        }
    }

    httpdStartResponse(conn, 200);
    httpdHeader(conn, "Content-Type", "text/json");
    httpdEndHeaders(conn);

    if(cgiWifiAps.scanInProgress == 1){
        //We're still scanning. Tell Javascript code that.
        len = sprintf(buff, "{\n \"result\": { \n\"inProgress\": \"1\"\n }\n}\n");
        httpdSend(conn, buff, len);
        return HTTPD_CGI_DONE;
    } else {
        //We have a scan result. Pass it on.
        len = sprintf(buff, "{\n \"result\": { \n\"inProgress\": \"0\", \n\"APs\": [\n");
        httpdSend(conn, buff, len);
        if(cgiWifiAps.apData == NULL){
            cgiWifiAps.noAps = 0;
        }

        conn->cgiData = (void *)1;
        return HTTPD_CGI_MORE;
    }
}

wifi_config_t wifi_config;
static void startSta(void)
{
    esp_err_t result;

    ESP_LOGI(TAG, "[%s] Connecting to ap SSID: %s", __func__, (char *)wifi_config.sta.ssid);

    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    connTryStatus = CONNTRY_WORKING;

    result = esp_wifi_connect();
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] esp_wifi_connect() failed.", __func__);
        connTryStatus = CONNTRY_FAIL;
    }

    ESP_LOGI(TAG, "wifi_init_sta finished");
}

//This cgi uses the routines above to connect to a specific access point with the
//given ESSID using the given password.
CgiStatus cgi_wifi_connect(HttpdConnData *conn)
{
    char essid[128];
    char passwd[128];

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
        return HTTPD_CGI_DONE;
    }

    httpdFindArg(conn->post.buff, "essid", essid, sizeof(essid));
    httpdFindArg(conn->post.buff, "passwd", passwd, sizeof(passwd));
    strncpy((char*)wifi_config.sta.ssid, essid, sizeof(wifi_config.sta.ssid));
    strncpy((char*)wifi_config.sta.password, passwd, sizeof(wifi_config.sta.password));

    ESP_LOGI(TAG, "Try to connect to AP %s pw %s", essid, passwd);

    startSta();

    httpdRedirect(conn, "connecting.html");

    return HTTPD_CGI_DONE;
}

//This cgi uses the routines above to connect to a specific access point with the
//given ESSID using the given password.
CgiStatus cgi_wifi_set_mode(HttpdConnData *conn)
{
    int len;
    char buff[1024];

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
        return HTTPD_CGI_DONE;
    }

    len=httpdFindArg(conn->getArgs, "mode", buff, sizeof(buff));
    if (len!=0) {
        esp_wifi_scan_stop();
        cgiWifiAps.scanInProgress = 0;
        // in wifi_mode_t, WIFI_MODE_STA = 1, WIFI_MODE_AP = 2, WIFI_MODE_APSTA = 3
        esp_wifi_set_mode(atoi(buff));
    }
    httpdRedirect(conn, "/wifi");
    return HTTPD_CGI_DONE;
}

//Set wifi channel for AP mode
CgiStatus cgi_wifi_set_chan(HttpdConnData *conn)
{
    int len;
    char buff[64];

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
        return HTTPD_CGI_DONE;
    }

    len=httpdFindArg(conn->getArgs, "ch", buff, sizeof(buff));
    if (len!=0) {
        int channel = atoi(buff);
        if (channel > 0 && channel < 15) {
            ESP_LOGI(TAG, "Setting ch=%d", channel);
            wifi_config_t wificfg;
            esp_wifi_get_config(ESP_IF_WIFI_AP, &wificfg);
            wificfg.ap.channel = (uint8)channel;
            esp_wifi_set_config(ESP_IF_WIFI_AP, &wificfg);
        }
    }
    httpdRedirect(conn, "/wifi");


    return HTTPD_CGI_DONE;
}

CgiStatus cgi_wifi_conn_status(HttpdConnData *conn)
{
    char buff[1024];
    int len;
    tcpip_adapter_ip_info_t info;
    wifi_ap_record_t wapr;
    esp_err_t connected;
    struct heph_wifi_cfg heph_cfg;
    esp_err_t result;

    httpdStartResponse(conn, 200);
    httpdHeader(conn, "Content-Type", "text/json");
    httpdEndHeaders(conn);

    if(connTryStatus == CONNTRY_FAIL){
        len=sprintf(buff, "{\n \"status\": \"fail\"\n}\n");
    } else {
        connected = esp_wifi_sta_get_ap_info(&wapr);
        tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &info);
        if(connected == ESP_OK && (info.ip.addr != IPADDR_ANY)){
            len = sprintf(buff, "{\n \"status\": \"success\",\n \"ip\": \"%s\"\n}\n",
                            ip4addr_ntoa(&(info.ip)));
            if(connTryStatus == CONNTRY_WORKING){
                connTryStatus = CONNTRY_SUCCESS;
            }
        } else {
            len=sprintf(buff, "{\n \"status\": \"working\"\n }\n");
        }
    }

    httpdSend(conn, buff, len);

    if(connTryStatus == CONNTRY_SUCCESS){
        memset(&heph_cfg, 0x0, sizeof(heph_cfg));
        strlcpy(heph_cfg.ssid, (char *) wifi_config.sta.ssid, sizeof(heph_cfg.ssid));
        strlcpy(heph_cfg.pass, (char *) wifi_config.sta.password, sizeof(heph_cfg.pass));

        result = heph_set_cfg(&heph_cfg, true);
        if(result == ESP_OK){
            ESP_LOGI(TAG, "[%s] Success setting new Heph WiFi config", __func__);
        } else {
            ESP_LOGE(TAG, "[%s] Error setting new Heph WiFi config", __func__);
        }

        connTryStatus = CONNTRY_IDLE;
    }

    return HTTPD_CGI_DONE;
}

int tpl_wlan(HttpdConnData *conn, char *token, void **arg)
{
    char buff[128];
    wifi_ap_record_t stconf;
    wifi_mode_t mode;
    esp_err_t result;

    if(token == NULL){
        goto err_out;
    }

    memset(buff, 0x0, sizeof(buff));

    if(strcmp(token, "WiFiMode") == 0){
        esp_wifi_get_mode(&mode);

        switch(mode){
        case WIFI_MODE_STA:
            strlcpy(buff, "Client", sizeof(buff));
            break;
        case WIFI_MODE_AP:
            strlcpy(buff, "SoftAP", sizeof(buff));
            break;
        case WIFI_MODE_APSTA:
            strlcpy(buff, "STA+AP", sizeof(buff));
            break;
        default:
            strlcpy(buff, "Unknown", sizeof(buff));
            break;
        }

    }else if(strcmp(token, "currSsid") == 0){
        result = esp_wifi_sta_get_ap_info(&stconf);
        if(result == ESP_OK){
            strlcpy(buff, (char*)stconf.ssid, sizeof(buff));
        }
    }else if(strcmp(token, "WiFiPasswd") == 0){
        strlcpy(buff, "********", sizeof(buff));
    }

    httpdSend(conn, buff, -1);

err_out:
    return HTTPD_CGI_DONE;
}

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
        httpdRedirect(conn, "/wifi");
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

    httpdFindArg(conn->post.buff, "fbox_user", cfg.fbox_user, sizeof(cfg.fbox_user));
    httpdFindArg(conn->post.buff, "fbox_pass", cfg.fbox_pass, sizeof(cfg.fbox_pass));
    httpdFindArg(conn->post.buff, "fbox_addr", cfg.fbox_addr, sizeof(cfg.fbox_addr));
    httpdFindArg(conn->post.buff, "fbox_port", cfg.fbox_port, sizeof(cfg.fbox_port));

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

struct dumper {
    struct aha_data *data;
    char buff[2048];
    size_t print_off;
    size_t send_off;
    unsigned int next;
    bool done;
};

struct tags {
    const char *group;
    const char *item;
};

static esp_err_t dump_tagged(struct dumper *dumper, const char *tag, const char *fmt, ...)
{
    va_list valist;
    char *buff;
    size_t remain;
    int printed;
    esp_err_t result;

    result = ESP_OK;
    buff = &(dumper->buff[dumper->print_off]);
    remain = sizeof(dumper->buff) - dumper->print_off;

    printed = snprintf(buff, remain, "<%s>", tag);
    if(printed < 0 || printed >= remain){
        ESP_LOGE(TAG, "[%s] Out of buffer space", __func__);
        result = ESP_ERR_INVALID_SIZE;
        goto err_out;
    }

    buff += printed;
    remain -= printed;

    va_start(valist, fmt);
    printed = vsnprintf(buff, remain, fmt, valist);
    va_end(valist);

    if(printed < 0 || printed >= remain){
        ESP_LOGE(TAG, "[%s] Out of buffer space", __func__);
        result = ESP_ERR_INVALID_SIZE;
        goto err_out;
    }

    buff += printed;
    remain -= printed;

    printed = snprintf(buff, remain, "</%s>\n", tag);
    if(printed < 0 || printed >= remain){
        ESP_LOGE(TAG, "[%s] Out of buffer space", __func__);
        result = ESP_ERR_INVALID_SIZE;
        goto err_out;
    }

    buff += printed;
    dumper->print_off = buff - dumper->buff;

err_out:
   return result;
}

static esp_err_t dump_untagged(struct dumper *dumper, const char *fmt, ...)
{
    va_list valist;
    char *buff;
    size_t remain;
    int printed;
    esp_err_t result;

    result = ESP_OK;
    buff = &(dumper->buff[dumper->print_off]);
    remain = sizeof(dumper->buff) - dumper->print_off;

    va_start(valist, fmt);
    printed = vsnprintf(buff, remain, fmt, valist);
    va_end(valist);

    if(printed < 0 || printed >= remain){
        ESP_LOGE(TAG, "[%s] Out of buffer space", __func__);
        result = ESP_ERR_INVALID_SIZE;
        goto err_out;
    }

    buff += printed;
    dumper->print_off = buff - dumper->buff;

err_out:
   return result;
}

static esp_err_t dump_hkr(HttpdConnData *conn, struct aha_hkr *hkr, struct tags *tags)
{
    struct dumper *dumper;
    esp_err_t result;

    result = ESP_OK;
    dumper = (struct dumper *) conn->cgiData;

    if(dumper == NULL){
        ESP_LOGE(TAG, "[%s] No dumper found!", __func__);
        result = ESP_ERR_INVALID_ARG;
        goto err_out;
    }

    if(hkr->present){
#if 0
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
#endif


        result = dump_tagged(dumper, tags->item, "Type: HKR");
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "<%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }

        result = dump_tagged(dumper, tags->item, "Set Temp: %lu", hkr->set_temp);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Actual Temp: %lu", hkr->act_temp);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Comfort Temp: %lu", hkr->comfort_temp);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Economic Temp: %lu", hkr->eco_temp);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Next Temp: %lu", hkr->next_temp);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Next Change: %lu", hkr->next_change);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Battery Low: %lu", hkr->batt_low);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Lock: %s",
                             hkr->lock == aha_lock_on ? "on" : "off");
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Device Lock: %s",
                             hkr->device_lock == aha_lock_on ? "on" : "off");
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Error Code: %lu", hkr->error);
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "</%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }
    }

err_out:
    return result;
}

static esp_err_t dump_swi(HttpdConnData *conn, struct aha_switch *swi, struct tags *tags)
{
    struct dumper *dumper;
    esp_err_t result;

    result = ESP_OK;
    dumper = (struct dumper *) conn->cgiData;

    if(dumper == NULL){
        ESP_LOGE(TAG, "[%s] No dumper found!", __func__);
        result = ESP_ERR_INVALID_ARG;
        goto err_out;
    }

    if(swi->present){
#if 0
        ESP_LOGI(TAG, "%s[SWI] State: %s Mode: %s Lock: %s DevLock: %s",
                 prefix,
                 swi->state == aha_swstate_on ? "on" : "off",
                 swi->mode == aha_switch_auto ? "auto" : "manual",
                 swi->lock == aha_lock_on ? "on" : "off",
                 swi->device_lock == aha_lock_on ? "on" : "off");
#endif

        result = dump_tagged(dumper, tags->item, "Type: Switch");
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "<%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }

        result = dump_tagged(dumper, tags->item, "State: %s",
                             swi->state == aha_swstate_on ? "on" : "off");
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Mode: %s",
                             swi->mode == aha_switch_auto ? "auto" : "manual");
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Lock: %s",
                             swi->device_lock == aha_lock_on ? "on" : "off");
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Device Lock: %s",
                             swi->device_lock == aha_lock_on ? "on" : "off");
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "</%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }
    }

err_out:
    return result;
}

static esp_err_t dump_temp(HttpdConnData *conn, struct aha_thermo *tmp, struct tags *tags)
{
    struct dumper *dumper;
    esp_err_t result;

    result = ESP_OK;
    dumper = (struct dumper *) conn->cgiData;

    if(dumper == NULL){
        ESP_LOGE(TAG, "[%s] No dumper found!", __func__);
        result = ESP_ERR_INVALID_ARG;
        goto err_out;
    }

    if(tmp->present){
#if 0
        ESP_LOGI(TAG, "%s[TMP] Temperature: %ld Offset: %ld",
                 prefix,
                 tmp->temp_c,
                 tmp->offset);
#endif
        result = dump_tagged(dumper, tags->item, "Type: Thermometer");
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "<%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }

        result = dump_tagged(dumper, tags->item, "Temperature: %lu", tmp->temp_c);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Offset: %lu", tmp->offset);
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "</%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }
    }

err_out:
    return result;
}

static esp_err_t dump_pwr(HttpdConnData *conn, struct aha_power *pwr, struct tags *tags)
{
    struct dumper *dumper;
    esp_err_t result;

    result = ESP_OK;
    dumper = (struct dumper *) conn->cgiData;

    if(dumper == NULL){
        ESP_LOGE(TAG, "[%s] No dumper found!", __func__);
        result = ESP_ERR_INVALID_ARG;
        goto err_out;
    }

    if(pwr->present){
#if 0
        ESP_LOGI(TAG, "%s[PWR] Power: %lu Energy: %lu",
                 prefix,
                 pwr->power,
                 pwr->energy);
#endif
        result = dump_tagged(dumper, tags->item, "Type: Powermeter");
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "<%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }

        result = dump_tagged(dumper, tags->item, "Power: %lu", pwr->power);
        if(result != ESP_OK){
            goto err_out;
        }

        result = dump_tagged(dumper, tags->item, "Energy: %lu", pwr->energy);
        if(result != ESP_OK){
            goto err_out;
        }

        if(tags->group != NULL && strlen(tags->group) > 0){
            result = dump_untagged(dumper, "</%s>\n", tags->group);
            if(result != ESP_OK){
                goto err_out;
            }
        }
    }

err_out:
    return result;
}

static esp_err_t dump_device(HttpdConnData *conn, struct aha_device *dev, struct tags *tags, unsigned int idx)
{
    struct dumper *dumper;
    esp_err_t result;

    result = ESP_OK;
    dumper = (struct dumper *) conn->cgiData;

    if(dumper == NULL){
        ESP_LOGE(TAG, "[%s] No dumper found!", __func__);
        result = ESP_ERR_INVALID_ARG;
        goto err_out;
    }

    if(idx != dumper->next){
        goto err_out;
    }

#if 0
    ESP_LOGI(TAG, "[%s] Name: %s ID: %lu Present: %lu Ident: %s FW: %s "
                  "Manuf: %s ProdName: %s Funcs: 0x%lx",
             dev->type == aha_type_device ? "DEV" : "GRP",
             dev->name,
             dev->id,
             dev->present,
             dev->identifier,
             dev->fw_version,
             dev->manufacturer,
             dev->product_name,
             dev->functions);
#endif

    result = dump_tagged(dumper, tags->item, "%s: %s",
                         dev->type == aha_type_device ? "[DEV]" : "[GRP]",
                         dev->name);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    if(tags->group != NULL && strlen(tags->group) > 0){
        result = dump_untagged(dumper, "<%s>\n", tags->group);
        if(result != ESP_OK){
            ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
            goto err_out;
        }
    }


    result = dump_tagged(dumper, tags->item, "ID: %lu", dev->id);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_tagged(dumper, tags->item, "Present: %lu", dev->present);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_tagged(dumper, tags->item, "Identifier: %s", dev->identifier);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_tagged(dumper, tags->item, "FW-Version: %s", dev->fw_version);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_tagged(dumper, tags->item, "Manufacturer: %s", dev->manufacturer);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_tagged(dumper, tags->item, "Product Name: %s", dev->product_name);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_tagged(dumper, tags->item, "Functions: 0x%lx", dev->functions);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
        goto err_out;
    }

    result = dump_hkr(conn, &(dev->hkr), tags);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] dump_hkr() failed", __func__);
        goto err_out;
    }

    dump_swi(conn, &(dev->swi), tags);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] dump_swi() failed", __func__);
        goto err_out;
    }

    dump_temp(conn, &(dev->temp), tags);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] dump_temp() failed", __func__);
        goto err_out;
    }

    dump_pwr(conn, &(dev->pwr), tags);
    if(result != ESP_OK){
        ESP_LOGE(TAG, "[%s] dump_pwr() failed", __func__);
        goto err_out;
    }

    if(tags->group != NULL && strlen(tags->group) > 0){
        result = dump_untagged(dumper, "</%s>\n", tags->group);
        if(result != ESP_OK){
            goto err_out;
        }
    }

err_out:
    return result;
}

CgiStatus cgi_aha_dump(HttpdConnData *conn)
{
    struct aha_device *dev, *grp;
    struct dumper *dumper;
    struct tags tags;
    unsigned int idx;
    esp_err_t status;
    size_t chunk_len;
    CgiStatus result;

    idx = 0;
    dumper = (struct dumper *) conn->cgiData;
    result = HTTPD_CGI_MORE;

    ESP_LOGD(TAG, "[%s] Called", __func__);

    if(conn->isConnectionClosed){
        ESP_LOGE(TAG, "[%s] Conn closed", __func__);
        result = HTTPD_CGI_DONE;
        goto err_out;
    }

    if(dumper == NULL){
        ESP_LOGD(TAG, "[%s] Allocating Dumper", __func__);
        dumper = calloc(1, sizeof(*dumper));
        if(dumper == NULL){
            ESP_LOGE(TAG, "Out of memory while dumping AHA data");
            goto err_out;
        }

        dumper->data = aha_data_get();
        if(dumper->data == NULL){
            ESP_LOGE(TAG, "[%s] No AHA data", __func__);
            result = HTTPD_CGI_DONE;
            goto err_out;
        }

        dumper->done = false;

        conn->cgiData = dumper;
        httpdStartResponse(conn, 200);
        httpdHeader(conn, "Content-Type", "text/html");
        httpdEndHeaders(conn);
        httpdSend(conn, "<html><head><title>AHA Data</title>"
                        "<link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\">"
                        "<meta http-equiv=\"refresh\" content=\"30\">"
                        "</head>"
                        "<body>"
                        "<div id=\"main\">"
                        "<p><ul>", -1);
    }

    ESP_LOGD(TAG, "enter: next: %d print: %d send: %d", dumper->next, dumper->print_off, dumper->send_off);
    if(dumper->print_off > 0 && dumper->print_off == dumper->send_off){
        dumper->print_off = 0;
        dumper->send_off = 0;
        dumper->next++;
        ESP_LOGD(TAG, "next dev: next: %d print: %d send: %d", dumper->next, dumper->print_off, dumper->send_off);
    }

    tags.group = "ul";
    tags.item = "li";

    if(dumper->print_off == 0){
        /* dump groups and its member devices */
        klist_for_each_entry(grp, &(dumper->data->grp_head), grp_list){
            status = dump_device(conn, grp, &tags, idx++);
            if(status != ESP_OK){
                ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
                result = HTTPD_CGI_DONE;
                goto err_out;
            }

            klist_for_each_entry(dev, &(grp->member_list), member_list){
                status = dump_device(conn, dev, &tags, idx++);
                if(status != ESP_OK){
                    ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
                    result = HTTPD_CGI_DONE;
                    goto err_out;
                }
            }
        }

        /* dump remaining devices not belonging to a group */
        klist_for_each_entry(dev, &(dumper->data->dev_head), dev_list){
            if(dev->group == NULL){
                status = dump_device(conn, dev, &tags, idx++);
                if(status != ESP_OK){
                    ESP_LOGE(TAG, "[%s] line %d failed", __func__, __LINE__);
                    result = HTTPD_CGI_DONE;
                    goto err_out;
                }
            }
        }

        if(idx <= dumper->next){
            dumper->done = true;
        }
    }

    if(dumper->print_off > dumper->send_off){
        ESP_LOGD(TAG, "pre send: next: %d print: %d send: %d", dumper->next, dumper->print_off, dumper->send_off);
        chunk_len = dumper->print_off - dumper->send_off;
        if(chunk_len > 128){
            chunk_len = 128;
        }

        if(httpdSend(conn, &(dumper->buff[dumper->send_off]), chunk_len)){
            dumper->send_off += chunk_len;
        }
        ESP_LOGD(TAG, "post send: next: %d print: %d send: %d", dumper->next, dumper->print_off, dumper->send_off);
    }

    ESP_LOGD(TAG, "post next: %d print: %d send: %d", dumper->next, dumper->print_off, dumper->send_off);
    ESP_LOGD(TAG, "post idx: %d next: %d result: %s", idx, dumper->next, result == HTTPD_CGI_DONE ? "done" :
                                                                         result == HTTPD_CGI_MORE ? "more" : "unknown");

    if(dumper->print_off == dumper->send_off && dumper->done == true){
        httpdSend(conn, "</ul></p></body></html>", -1);
        result = HTTPD_CGI_DONE;
    }

err_out:
    if(result == HTTPD_CGI_DONE && dumper != NULL){
        ESP_LOGD(TAG, "[%s] Cleaning up", __func__);
        aha_data_release(dumper->data);
        free(dumper);
    }

    return result;
}

