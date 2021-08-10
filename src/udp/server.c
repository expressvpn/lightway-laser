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

#include "server.h"
#include "flow.h"
#include "util.h"

void configure_udp_server(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring UDP Server...\n");

  int res = uv_udp_init(state->loop, &state->udp_socket);
  LW_CHECK_WITH_MSG(res == 0, "Unable to initialise UDP socket");

  struct sockaddr_in recv_addr;
  res = uv_ip4_addr(config->server_ip, config->server_port, &recv_addr);
  LW_CHECK_WITH_MSG(res == 0, "Invalid IP address or port");

  res = uv_udp_bind(&state->udp_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
  LW_CHECK_WITH_MSG(res == 0, "Unable to bind UDP socket");

  int udp_buffer_size = 15 * MEGABYTE;
  uv_send_buffer_size((uv_handle_t *)&state->udp_socket, &udp_buffer_size);
  uv_recv_buffer_size((uv_handle_t *)&state->udp_socket, &udp_buffer_size);

  state->udp_socket.data = state;
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, udp_write_cb);

  return;
}

void start_udp_server(lw_state_t *state) {
  int res = uv_udp_recv_start(&state->udp_socket, alloc_buffer, on_read);
  LW_CHECK_WITH_MSG(res == 0, "Unable to start recv on udp socket");

  return;
}
