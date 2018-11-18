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

#ifndef _AVM_AHA_
#define _AVM_AHA_

#include "heph_types.h"

#include <time.h>
#include "klist.h"
#include "kref.h"

struct aha_data
{
    struct kref ref_cnt;
    time_t timestamp;
    int status;
    const char *msg;
    struct klist_head dev_head; // list of all devices
    struct klist_head grp_head; // list of all groups
};

#define AHA_ENTRY_LEN   128
#define AHA_MAX_MEMBERS 16
#define AHA_NVS_NAMESPC "avm_aha"

#define HEAT_FORCE_ON   0xFE
#define HEAT_FORCE_OFF  0xFD

enum aha_heat_mode {
    aha_heat_off = 0,
    aha_heat_keep,
    aha_heat_on
};

enum aha_entry_type
{
    aha_type_invalid = 0,
    aha_type_device,
    aha_type_group,
};

enum aha_lock_mode
{
    aha_lock_unknown = 0,
    aha_lock_on,
    aha_lock_off,
};

enum aha_switch_mode
{
    aha_switch_unknown = 0,
    aha_switch_auto,
    aha_switch_manual,
};

enum aha_switch_state
{
    aha_swstate_unknown = 0,
    aha_swstate_on,
    aha_swstate_off,
};

enum aha_alarm_mode
{
    aha_alarm_unknown = 0,
    aha_alarm_off,
    aha_alarm_on,
};

struct aha_hkr
{
    bool present;
    unsigned long set_temp;
    unsigned long act_temp;
    unsigned long comfort_temp;
    unsigned long eco_temp;
    unsigned long batt_low;
    unsigned long window_open;
    unsigned long next_temp;
    unsigned long next_change;
    enum aha_lock_mode lock;
    enum aha_lock_mode device_lock;
    unsigned long error;
};

struct aha_switch
{
    bool present;
    enum aha_switch_state state;
    enum aha_switch_mode mode;
    enum aha_lock_mode lock;
    enum aha_lock_mode device_lock;
};

struct aha_power
{
    bool present;
    unsigned long power;
    unsigned long energy;
};

struct aha_thermo
{
    bool present;
    long temp_c;
    long offset;
};

struct aha_alarm
{
    bool present;
    enum aha_alarm_mode mode;
};

struct aha_button
{
    bool present;
    unsigned long last_pressed;
};

struct aha_group
{
    bool present;
    unsigned long master_dev;
    unsigned long members[AHA_MAX_MEMBERS];
    unsigned int member_cnt;
};

struct aha_device
{   
    struct klist_head dev_list;
    struct klist_head grp_list;
    struct klist_head member_list;
    enum aha_entry_type type;
    char name[AHA_ENTRY_LEN];
    char identifier[AHA_ENTRY_LEN];
    char fw_version[AHA_ENTRY_LEN];
    char manufacturer[AHA_ENTRY_LEN];
    char product_name[AHA_ENTRY_LEN];
    unsigned long functions;
    unsigned long id;
    unsigned long present;
    struct aha_device *group;
    struct aha_group grp;
    struct aha_switch swi;
    struct aha_power pwr;
    struct aha_thermo temp;
    struct aha_alarm alarm;
    struct aha_button button;
    struct aha_hkr hkr;
};


extern void avm_aha_task(void *pvParameters);
extern struct aha_data *aha_data_get(void);
extern void aha_data_release(struct aha_data *data);
extern esp_err_t aha_get_cfg(struct aha_cfg *cfg, enum cfg_load_type from);
extern esp_err_t aha_set_cfg(struct aha_cfg *cfg, bool reload);
extern void aha_task_suspend(void);
extern void aha_task_resume(void);

#endif // _AVM_AHA_

