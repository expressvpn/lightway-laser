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

#ifndef LW_TUN_H
#define LW_TUN_H

#include <lw.h>

void configure_tunnel_server(lw_config_t *config, lw_state_t *state);
void start_tunnel_server(lw_state_t *state);

void configure_tunnel_client(lw_config_t *config, lw_state_t *state);
// Note that there is no "start" for clients; the tunnel is started during the connection process

#endif  // LW_TUN_H
