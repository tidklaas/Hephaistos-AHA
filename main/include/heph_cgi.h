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
extern CgiStatus cgi_wifi_reset(HttpdConnData *conn);
extern CgiStatus cgi_wifi_conn_status(HttpdConnData *conn);

extern int tpl_main(HttpdConnData *conn, char *token, void **arg);
extern int tpl_user(HttpdConnData *conn, char *token, void **arg);
extern CgiStatus cgi_user_set(HttpdConnData *conn);

extern int tpl_ahacfg(HttpdConnData *conn, char *token, void **arg);
extern CgiStatus cgi_aha_setcfg(HttpdConnData *conn);

extern CgiStatus cgi_aha_dump(HttpdConnData *conn);

#endif /* _HEPH_CGI_H_ */
