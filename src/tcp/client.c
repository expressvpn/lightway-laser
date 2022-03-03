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

#include "client.h"
#include "flow.h"
#include "util.h"

#define DEFAULT_BACKLOG 128

void configure_tcp_client(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring TCP Client...\n");

  int res = uv_tcp_init(state->loop, &state->tcp_socket);
  LW_CHECK_WITH_MSG(res == 0, "Unable to initialise TCP socket");

  res = uv_ip4_addr(config->server_ip, config->server_port, &state->send_addr);
  LW_CHECK_WITH_MSG(res == 0, "Invalid IP address or port");

  int tcp_buffer_size = 15 * MEGABYTE;
  uv_send_buffer_size((uv_handle_t *)&state->tcp_socket, &tcp_buffer_size);
  uv_recv_buffer_size((uv_handle_t *)&state->tcp_socket, &tcp_buffer_size);

/* Connect to server */
  uv_connect_t *connect = (uv_connect_t *)calloc(1,sizeof(uv_connect_t));
  res = uv_tcp_connect(connect,&state->tcp_socket,(const struct sockaddr *)&state->send_addr,on_connect);
  LW_CHECK_WITH_MSG(res == 0, "Unable to connect to tcp server");

  state->tcp_socket.data = state;
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, tcp_write_cb);

  return;
}

void start_tcp_client(lw_state_t *state) {

  int res = uv_read_start((uv_stream_t *)&state->tcp_socket, alloc_buffer, on_read);
  LW_CHECK_WITH_MSG(res == 0, "Unable to start recv on tcp socket");

  return;
}
