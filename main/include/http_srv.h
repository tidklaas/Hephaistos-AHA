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

#ifndef _HTTP_SRV_H_
#define _HTTP_SRV_H_

#include "heph_types.h"

#define HTTP_NVS_NAMESPC    "http_srv"

extern esp_err_t http_srv_init(void);
extern esp_err_t http_get_cfg(struct http_srv_cfg *cfg, enum cfg_load_type from);
extern esp_err_t http_set_cfg(struct http_srv_cfg *cfg, bool reload);
extern void wifi_scan_done_cb(void);

#endif /* _HTTP_SRV_H_ */
