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

#include "tun_network.h"

// Following header from:
// https://stackoverflow.com/questions/16519846/parse-ip-and-tcp-header-especially-common-tcp-header-optionsof-packets-capture
#pragma pack(1)
typedef struct {
  uint8_t ver_ihl;  // 4 bits version and 4 bits internet header length
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo;  // 3 bits flags and 13 bits fragment-offset
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_addr;
  uint32_t dst_addr;
} ipv4_header_t;

#pragma pack()

he_packet_state_t he_internal_packet_type(uint8_t *packet, size_t length) {
  // IPv4 is the smallest header for packets we accept
  if(length < sizeof(ipv4_header_t)) {
    return HE_BAD_PACKET;
  }

  // Bits 0-4 of packet contain the IP version
  uint8_t proto = packet[0] >> 4;
  switch(proto) {
    case 4:
      return HE_PACKET_IP4;
    case 6:
      return HE_PACKET_IP6;
    default:
      return HE_BAD_PACKET;
  }
}
