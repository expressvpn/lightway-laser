/* *
 * Lightway Laser
 * Copyright (C) 2021 Express VPN International Ltd.
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

#ifndef LW_TUN_NETWORK_H
#define LW_TUN_NETWORK_H

#include <stdint.h>

#include <lw.h>

typedef enum he_packet_state {
  HE_BAD_PACKET = 0,
  HE_PACKET_IP4 = 1,
  HE_PACKET_IP6 = 2
} he_packet_state_t;

he_packet_state_t he_internal_packet_type(uint8_t *packet, size_t length);

#endif  // LW_TUN_NETWORK_H
