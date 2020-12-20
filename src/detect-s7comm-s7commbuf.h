/* Copyright (C) 2015-2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 */

#ifndef __DETECT_S7COMM_S7COMMBUF_H__
#define __DETECT_S7COMM_S7COMMBUF_H__

#include "app-layer-s7comm.h"

typedef struct DetectS7comm_ {
    uint8_t             type;     
    uint8_t             function;  
    bool has_type;
    bool has_function;                  
    //DetectModbusValue   *unit_id;         
    //DetectModbusValue   *address;          
    //DetectModbusValue   *data;             
} DetectS7comm;

void DetectS7commS7commbufRegister(void);

#endif /* __DETECT_S7COMM_S7COMMBUF_H__ */
