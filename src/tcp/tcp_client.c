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

#include "tcp_client.h"
#include "tcp_flow.h"
#include "helium.h"
#include "util.h"

void configure_tcp_client(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring TCP Client...\n");

  int res = uv_tcp_init(state->loop, &state->tcp_client);
  LW_CHECK_WITH_MSG(res == 0, "Unable to initialise TCP socket");

  res = uv_ip4_addr(config->server_ip, config->server_port, &state->send_addr);
  LW_CHECK_WITH_MSG(res == 0, "Invalid IP address or port");

  state->tcp_client.data = state;
  he_ssl_ctx_set_outside_write_cb(state->he_ctx, tcp_write_cb);

  return;
}

void on_tcp_connect(uv_connect_t *connect, int status) {
  lw_state_t *state = (lw_state_t *)connect->data;

  if (status < 0) {
    zlogf(ZLOG_INFO_LOG_MSG, "Connect failed\n");
    return;
  }
  connect->handle->data = state;
  status = uv_read_start(connect->handle, alloc_tcp_buffer, on_tcp_read);

  zlogf(ZLOG_INFO_LOG_MSG, "TCP Connected\n");
  start_helium_client(state);
}

void start_tcp_client(lw_state_t *state) {
  state->tcp_connect.data = state;
  int res = uv_tcp_connect(&state->tcp_connect, &state->tcp_client, &state->send_addr, on_tcp_connect);
  LW_CHECK_WITH_MSG(res == 0, "Unable to connect on tcp socket");

  return;
}
