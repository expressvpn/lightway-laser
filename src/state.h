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

#ifndef LW_STATE_H
#define LW_STATE_H

#include <lw.h>

lw_state_t *lw_start_server(lw_config_t *config);

void lw_state_server_connect(lw_state_t *state, const struct sockaddr *addr);
void lw_state_disconnect(lw_state_t *state);
void lw_state_post_disconnect_cleanup(lw_state_t *state);

lw_state_t *lw_start_client(lw_config_t *config);

#endif  // LW_STATE_H
