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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#ifndef _HEPH_TYPES_H_
#define _HEPH_TYPES_H_

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))
#endif

#define HEPH_AP_SSID        "Hephaistos"
#define HEPH_NVS_NAMESPC    "hephaistos"
#define MAX_SSID_LEN        33
#define MAX_PASS_LEN        33
#define MAX_TZ_LEN          65

struct heph_cfg {
    char tz[MAX_TZ_LEN];
};

#define HTTP_USER_LEN       32
#define HTTP_PASS_LEN       32

struct http_srv_cfg {
    char user[HTTP_USER_LEN];
    char pass[HTTP_PASS_LEN];
};

#define AHA_CFG_MAXLEN  64

struct aha_cfg {
    char fbox_user[AHA_CFG_MAXLEN];
    char fbox_pass[AHA_CFG_MAXLEN];
    char fbox_addr[AHA_CFG_MAXLEN];
    char fbox_port[AHA_CFG_MAXLEN];
};

enum cfg_load_type {
    cfg_nvs,
    cfg_ram,
};

#endif // _HEPH_TYPES_H_

