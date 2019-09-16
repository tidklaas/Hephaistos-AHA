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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#ifndef _HEPHAISTOS_H_
#define _HEPHAISTOS_H_

#include "heph_types.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))
#endif

#define HEPH_AP_SSID        "Hephaistos"
#define HEPH_NVS_NAMESPC    "hephaistos"

extern esp_err_t heph_connected(void);
extern esp_err_t heph_get_cfg(struct heph_cfg *cfg, enum cfg_load_type from);
extern esp_err_t heph_set_cfg(struct heph_cfg *cfg, bool reload);
extern void heph_led_set(bool on);
extern void heph_heat_set(bool on);

#endif // _HEPHAISTOS_H_

