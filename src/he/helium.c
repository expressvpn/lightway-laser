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

#include "helium.h"

#include "util.h"
#include "state.h"

bool auth_cb(he_conn_t *he_conn, char const *username, char const *password, void *context) {
  lw_state_t *state = (lw_state_t *)context;

  int username_compare = strncmp(state->username, username, sizeof(state->username));
  // Of course we know that auth fails if the password comparison fails, but we want
  // to make sure that the same amount of time passes for auth success and failure
  int password_compare = strncmp(state->password, password, sizeof(state->password));

  return (username_compare == 0) && (password_compare == 0);
}

he_return_code_t populate_network_config_ipv4_cb(he_conn_t *he_conn,
                                                 he_network_config_ipv4_t *config, void *context) {
  lw_state_t *state = (lw_state_t *)context;

  // Copy the homogonized network configuration into the auth response
  strncpy(config->local_ip, state->client_ip, sizeof(config->local_ip));
  strncpy(config->peer_ip, state->peer_ip, sizeof(config->peer_ip));
  strncpy(config->dns_ip, state->dns_ip, sizeof(config->dns_ip));
  config->mtu = LW_MAX_INSIDE_MTU;

  return HE_SUCCESS;
}

void on_he_nudge(uv_timer_t *timer) {
  // Grab connection context
  lw_state_t *state = (lw_state_t *)timer->data;

  he_conn_nudge(state->he_conn);
}

he_return_code_t nudge_time_cb(he_conn_t *client, int timeout, void *context) {
  // Get our context back
  lw_state_t *state = (lw_state_t *)context;

  // Schedule new timeout
  int res = uv_timer_start(&state->he_timer, on_he_nudge, (u_int64_t)timeout, 0);
  if(res < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_timer_start: %s\n", uv_strerror(res));
    return HE_ERR_CALLBACK_FAILED;
  }
  zlogf_time(ZLOG_INFO_LOG_MSG, "Scheduling Helium nudge in %ld ms\n", timeout);
  return HE_SUCCESS;
}

he_return_code_t server_event_cb(he_conn_t *client, he_conn_event_t event, void *context) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Event occurred %d\n", event);

  return HE_SUCCESS;
}

he_return_code_t state_change_cb(he_conn_t *client, he_conn_state_t new_state, void *context) {
  // Get our context back
  lw_state_t *state = (lw_state_t *)context;

  zlogf_time(ZLOG_INFO_LOG_MSG, "State changed %d\n", new_state);

  if(new_state == HE_STATE_DISCONNECTED) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Helium connection was disconnected\n");
    lw_state_post_disconnect_cleanup(state);
  }

  return HE_SUCCESS;
}

void configure_helium_shared(lw_config_t *config, lw_state_t *state) {
  // Return code holder for the various functions
  // Note that if we get anything besides success here we just die, no cleanup
  int res = 0;

  // Initialise libhelium
  res = he_init();
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to initialise libhelium");

  state->he_ctx = he_ssl_ctx_create();
  LW_CHECK_WITH_MSG(state->he_ctx, "Failed to create SSL context");

  if(config->streaming) {
    res = he_ssl_ctx_set_connection_type(state->he_ctx, HE_CONNECTION_TYPE_STREAM);
  } else {
    res = he_ssl_ctx_set_connection_type(state->he_ctx, HE_CONNECTION_TYPE_DATAGRAM);
  }
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set the connection type");
  he_ssl_ctx_set_nudge_time_cb(state->he_ctx, nudge_time_cb);

  he_ssl_ctx_set_event_cb(state->he_ctx, server_event_cb);

  he_ssl_ctx_set_state_change_cb(state->he_ctx, state_change_cb);

  res = uv_timer_init(state->loop, &state->he_timer);
  LW_CHECK_WITH_MSG(res == 0, "Failed to initialise the Helium timer");
  state->he_timer.data = state;
}

void configure_helium_server(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring Helium Server...\n");

  configure_helium_shared(config, state);

  // Return code holder for the various functions
  // Note that if we get anything besides success here we just die, no cleanup
  int res = 0;

  // Initialise libhelium

  res = he_ssl_ctx_set_server_cert_key_files(state->he_ctx, config->crt_path,
                                             config->server_key_path);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set the server key path");

  he_ssl_ctx_set_auth_cb(state->he_ctx, auth_cb);
  he_ssl_ctx_set_populate_network_config_ipv4_cb(state->he_ctx, populate_network_config_ipv4_cb);

  return;
}

void start_helium_server(lw_state_t *state) {
  // Easy!
  int res = he_ssl_ctx_start_server(state->he_ctx);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to start the server context");
}

void start_helium_server_connection(lw_state_t *state) {
  state->he_conn = he_conn_create();
  LW_CHECK_WITH_MSG(state->he_conn, "Unable to allocate new Helium connection");

  int res = he_conn_set_outside_mtu(state->he_conn, LW_MAX_WIRE_MTU);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Unable to set outside MTU");

  res = he_conn_set_context(state->he_conn, state);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Unable to set context");

  res = he_conn_server_connect(state->he_conn, state->he_ctx, NULL, NULL);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Helium connect failed");
}

void configure_helium_client(lw_config_t *config, lw_state_t *state) {
  zlogf_time(ZLOG_INFO_LOG_MSG, "Configuring Helium client...\n");
  configure_helium_shared(config, state);

  // Return code holder for the various functions
  // Note that if we get anything besides success here we just die, no cleanup
  int res = 0;

  char *ca_buf = NULL;
  size_t length = slurp_file(config->crt_path, &ca_buf);
  LW_CHECK_WITH_MSG(length > 0, "Unable to slurp certificate file");
  res = he_ssl_ctx_set_ca(state->he_ctx, ca_buf, length);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set the server key path");

  state->he_conn = he_conn_create();
  LW_CHECK_WITH_MSG(state->he_conn, "Failed to create connection");

  res = he_conn_set_username(state->he_conn, config->username);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set username");

  res = he_conn_set_password(state->he_conn, config->password);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set password");

  res = he_conn_set_outside_mtu(state->he_conn, LW_MAX_WIRE_MTU);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set outside MTU");

  res = he_conn_set_context(state->he_conn, state);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to set the context");

  return;
}

void start_helium_client(lw_state_t *state) {
  // First we do the client->wolf_ctx setup
  int res = he_ssl_ctx_start(state->he_ctx);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to start He context!");

  res = he_conn_client_connect(state->he_conn, state->he_ctx, NULL, NULL);
  LW_CHECK_WITH_MSG(res == HE_SUCCESS, "Failed to connect!");
}
