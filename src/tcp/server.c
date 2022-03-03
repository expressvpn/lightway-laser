/*
  TODO:
    - check flow.c
    - check buffer
    - Implement accepting new clients and processing information
*/


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

#define DEFAULT_BACKLOG 128

void configure_tcp_server(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring TCP Server...\n");

  int res = uv_tcp_init(state->loop, &state->tcp_socket);
  LW_CHECK_WITH_MSG(res == 0, "Unable to initialise TCP server");

  struct sockaddr_in recv_addr;
  res = uv_ip4_addr(config->server_ip, config->server_port, &recv_addr);
  LW_CHECK_WITH_MSG(res == 0, "Invalid IP address or port");

  res = uv_tcp_bind(&state->tcp_socket, (const struct sockaddr *)&recv_addr, 0);
  LW_CHECK_WITH_MSG(res == 0, "Unable to bind TCP socket");

  int tcp_buffer_size = 15 * MEGABYTE;
  uv_send_buffer_size((uv_handle_t *)&state->tcp_socket, &tcp_buffer_size);
  uv_recv_buffer_size((uv_handle_t *)&state->tcp_socket, &tcp_buffer_size);


  state->tcp_socket.data = state;
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, tcp_write_cb);

  return;
}

void start_tcp_server(lw_state_t *state) {
  /* Listening on the socket for new clients */
  int res = uv_listen((uv_stream_t *)&state->tcp_socket, DEFAULT_BACKLOG, on_new_connection);
  LW_CHECK_WITH_MSG(res == 0, "Unable to start listen on tcp socket");

  return;
}
