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

#include "tcp_server.h"
#include "tcp_flow.h"
#include "state.h"
#include "util.h"

void configure_tcp_server(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring TCP Server...\n");

  int res = uv_tcp_init(state->loop, &state->tcp_socket);
  LW_CHECK_WITH_MSG(res == 0, "Unable to initialise TCP socket");

  struct sockaddr_in recv_addr;
  res = uv_ip4_addr(config->server_ip, config->server_port, &recv_addr);
  LW_CHECK_WITH_MSG(res == 0, "Invalid IP address or port");

  res = uv_tcp_bind(&state->tcp_socket, (const struct sockaddr *)&recv_addr, 0);
  LW_CHECK_WITH_MSG(res == 0, "Unable to bind UDP socket");

  state->tcp_socket.data = state;
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, tcp_write_cb);

  return;
}

void start_tcp_server(lw_state_t *state) {
  int res = uv_listen((uv_stream_t *)&state->tcp_socket, 128, on_new_connection);
  LW_CHECK_WITH_MSG(res == 0, "Unable to start recv on udp socket");

  return;
}

void on_new_connection(uv_stream_t *stream, int status) {
  LW_CHECK_WITH_MSG(stream, "Stream is null");

  lw_state_t *state = (lw_state_t *)stream->data;

  if (status < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "New connection error %s\n", uv_strerror(status));
    return;
  }

  lw_state_server_connect(state, NULL);

  status = uv_tcp_init(state->loop, &state->tcp_client);

  if (status != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Init TCP error %s\n", uv_strerror(status));
  }

  status = uv_accept(stream, (uv_stream_t *)&state->tcp_client);

  if (status != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Accept error %s\n", uv_strerror(status));
  }

  state->tcp_client.data = state;

  status = uv_read_start((uv_stream_t *) &state->tcp_client, alloc_tcp_buffer, on_tcp_read);

  if (status != 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Read start error %s\n", uv_strerror(status));
  }
}
