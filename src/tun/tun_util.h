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

#ifndef LW_TUN_UTIL_H
#define LW_TUN_UTIL_H

#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>

int tun_alloc(char *dev, int flags);
void tun_set_ip_internal(const char *tun_name, const char *local_ip, const char *peer_ip,
                         const int mtu);

// A convenience function to abstract away the write system call for testing
void write_to_tun(int tun_fd, uint8_t *buffer, int length);

// A convenience function to allow us to abstract away the read system call for testing
ssize_t read_from_tun(int tun_fd, void *buf, size_t count);

#endif  // LW_TUN_UTIL_H
