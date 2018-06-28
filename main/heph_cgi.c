/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
   Cgi/template routines for the /wifi url.
 */


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

#define CONNTRY_IDLE 0
#define CONNTRY_WORKING 1
#define CONNTRY_SUCCESS 2
#define CONNTRY_FAIL 3

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
    esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    ESP_ERROR_CHECK( esp_wifi_connect());
    connTryStatus = CONNTRY_SUCCESS;
    ESP_LOGI(TAG, "wifi_init_sta finished");
    ESP_LOGI(TAG, "connect to ap SSID:%s", (char *)wifi_config.sta.ssid);
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
    connTryStatus = CONNTRY_WORKING;
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

    switch(connTryStatus){
        case CONNTRY_IDLE:
            len = sprintf(buff, "{\n \"status\": \"idle\"\n }\n");
            break;
        case CONNTRY_WORKING:
        case CONNTRY_SUCCESS:
            connected = esp_wifi_sta_get_ap_info(&wapr);
            tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &info);
            if(connected == ESP_OK && (info.ip.addr != IPADDR_ANY)){
                len = sprintf(buff, "{\n \"status\": \"success\",\n \"ip\": \"%s\" }\n",
                                ip4addr_ntoa(&(info.ip)));

            } else {
                len=sprintf(buff, "{\n \"status\": \"working\"\n }\n");
            }
            break;
        default:
            len=sprintf(buff, "{\n \"status\": \"fail\"\n }\n");
            break;
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

    /* Force setting of new user credentials */
    result = http_get_cfg(&http_cfg);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/user/");
        goto err_out;
    }

    /* Force setting of WiFi connection */
    result = heph_get_cfg(&heph_cfg);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/wifi");
        goto err_out;
    }

    /* Force setting of AHA config */
    result = aha_get_cfg(&aha_cfg);
    if(result != ESP_OK){
        // FIXME: handle temporary error
        httpdRedirect(conn, "/aha/setup.tpl");
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
    struct http_srv_cfg http_cfg;
    esp_err_t result;

    if (conn->isConnectionClosed) {
        //Connection aborted. Clean up.
        return HTTPD_CGI_DONE;
    }

    memset(&http_cfg, 0x0, sizeof(http_cfg));

    httpdFindArg(conn->post.buff, "user", http_cfg.user, sizeof(http_cfg.user));
    httpdFindArg(conn->post.buff, "pass", http_cfg.pass, sizeof(http_cfg.pass));

    if(strlen(http_cfg.user) > 0 || strlen(http_cfg.pass) > 0){
        result = http_set_cfg(&http_cfg, true);
        if(result == ESP_OK){
            httpdRedirect(conn, "/");
            goto err_out;
        }
    }

    httpdRedirect(conn, "/user");

err_out:
    return HTTPD_CGI_DONE;
}

