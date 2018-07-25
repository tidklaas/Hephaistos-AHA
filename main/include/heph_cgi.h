#ifndef _HEPH_CGI_H_
#define _HEPH_CGI_H_

#include <libesphttpd/httpd.h>

extern CgiStatus cgi_redirect(HttpdConnData *conn);

extern int tpl_wlan(HttpdConnData *conn, char *token, void **arg);
extern CgiStatus cgi_wifi_scan(HttpdConnData *conn);
extern CgiStatus cgi_wifi(HttpdConnData *conn);
extern CgiStatus cgi_wifi_connect(HttpdConnData *conn);
extern CgiStatus cgi_wifi_set_mode(HttpdConnData *conn);
extern CgiStatus cgi_wifi_set_chan(HttpdConnData *conn);
extern CgiStatus cgi_wifi_conn_status(HttpdConnData *conn);

extern int tpl_user(HttpdConnData *conn, char *token, void **arg);
extern CgiStatus cgi_user_set(HttpdConnData *conn);

extern int tpl_ahacfg(HttpdConnData *conn, char *token, void **arg);
extern CgiStatus cgi_aha_setcfg(HttpdConnData *conn);

extern CgiStatus cgi_aha_dump(HttpdConnData *conn);

#endif // _HEPH_CGI_H_
