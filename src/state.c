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

#include "state.h"

#include "util.h"
#include "he/helium.h"
#include "tcp/server.h"
#include "tcp/client.h"
#include "tun/tun.h"

lw_state_t *lw_start_server(lw_config_t *config) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Starting server...\n");

  zlogf_time(ZLOG_INFO_LOG_MSG, "Listening on:         %s:%d\n", config->server_ip,
             config->server_port);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Username:             %s\n", config->username);

  zlogf_time(ZLOG_INFO_LOG_MSG, "Server cert:          %s\n", config->crt_path);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Server key:           %s\n", config->server_key_path);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Streaming Mode:       %s\n", config->streaming ? "true" : "false");
  zlogf_time(ZLOG_INFO_LOG_MSG, "Tun device:           %s\n", config->tun_name);
  zlog_flush_buffer();

  // Call sequence is Configure, then start, for helium -> UDP/TCP -> Tunnel
  lw_state_t *state = calloc(1, sizeof(lw_state_t));
  LW_CHECK_WITH_MSG(state, "Unable to allocate state");

  state->is_server = true;

  // Copy the username and password as-is
  // strnlen returns min(index offirst null terminator, HE_CONFIG_TEXT_FIELD_LENGTH), won't run to
  // infinity
  strncpy(state->username, config->username, sizeof(state->username));
  state->username[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';
  strncpy(state->password, config->password, sizeof(state->password));
  state->password[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';

  // Also copy the tun_name as-is
  strncpy(state->tun_name, config->tun_name, sizeof(state->tun_name));

  // Initialise these w/ hardcoded values for now
  state->peer_ip = "10.125.0.1";
  state->client_ip = "10.125.0.2";
  state->client_ip_u32 = ip2int("10.125.0.2");
  state->dns_ip = "8.8.8.8";

  // Initialise libuv
  state->loop = uv_default_loop();
  LW_CHECK_WITH_MSG(state->loop, "Unable to obtain default libuv loop");

  configure_helium_server(config, state);

  if(config->streaming) {
    configure_tcp_server(config, state);
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "UDP module not implemented");
    LW_EXIT_WITH_FAILURE();
  }

  // Configure Tunnel
  configure_tunnel_server(config, state);

  start_helium_server(state);

  if(config->streaming) {
    start_tcp_server(state);
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "UDP module not impplemented");
    LW_EXIT_WITH_FAILURE();
  }

  start_tunnel_server(state);

  return state;
}

void on_client_kickstart(uv_timer_t *timer) {
  lw_state_t *state = (lw_state_t *)timer->data;

  zlogf_time(ZLOG_INFO_LOG_MSG, "Kickstarting client\n");

  start_helium_client(state);

  start_tcp_client(state);

  // We don't start the tunnel here, but instead during the network_config callback
}

lw_state_t *lw_start_client(lw_config_t *config) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Starting client...\n");

  zlogf_time(ZLOG_INFO_LOG_MSG, "Connecting to:        %s:%d\n", config->server_ip,
             config->server_port);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Username:             %s\n", config->username);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Client cert:          %s\n", config->crt_path);
  zlogf_time(ZLOG_INFO_LOG_MSG, "Streaming Mode:       %s\n", config->streaming ? "true" : "false");
  zlogf_time(ZLOG_INFO_LOG_MSG, "Tun device:           %s\n", config->tun_name);
  zlog_flush_buffer();

  // Call sequence is Configure, then start, for helium -> UDP/TCP -> Tunnel
  lw_state_t *state = calloc(1, sizeof(lw_state_t));
  LW_CHECK_WITH_MSG(state, "Unable to allocate state");

  state->is_server = false;

  // Copy the username and password as-is
  // strnlen returns min(index offirst null terminator, HE_CONFIG_TEXT_FIELD_LENGTH), won't run to
  // infinity
  strncpy(state->username, config->username, sizeof(state->username));
  state->username[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';
  strncpy(state->password, config->password, sizeof(state->password));
  state->password[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';

  // Also copy the tun_name as-is
  strncpy(state->tun_name, config->tun_name, sizeof(state->tun_name));
  state->password[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';

  // Initialise libuv
  state->loop = uv_default_loop();
  LW_CHECK_WITH_MSG(state->loop, "Unable to obtain default libuv loop");

  configure_helium_client(config, state);

  if(config->streaming) {
    configure_tcp_client(config, state);
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "UDP not supported yet");
    LW_EXIT_WITH_FAILURE();
  }

  configure_tunnel_client(config, state);

  uv_timer_start(&state->he_timer, on_client_kickstart, 0, 0);

  return state;
}

void lw_state_post_disconnect_cleanup(lw_state_t *state) {
  uv_timer_stop(&state->he_timer);
  he_conn_destroy(state->he_conn);
  state->he_conn = NULL;
  state->session = 0;
  state->assigned_ip = 0;
  memset(&state->send_addr, 0, sizeof(state->send_addr));
}

void lw_state_disconnect(lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Closing connection w/ session ID %x\n", state->session);
  int res = he_conn_disconnect(state->he_conn);

  // If this is successful we expect to get called by the state change handler, but if it's not we
  // esxpect to clean up anyway
  if(res != HE_SUCCESS) {
    lw_state_post_disconnect_cleanup(state);
  }
}

void lw_state_server_connect(lw_state_t *state, const struct sockaddr *addr) {
  start_helium_server_connection(state);

  // Copy the IP address and session
  memcpy(&state->send_addr, addr, sizeof(struct sockaddr));
  state->session = he_conn_get_session_id(state->he_conn);
  state->assigned_ip = ip2int("10.125.0.42");
}
