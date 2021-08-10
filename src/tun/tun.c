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

#include "tun.h"

#include "tun_network.h"
#include "tun_util.h"
#include "util.h"

static he_return_code_t tun_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length,
                                     void *context) {
  // Get our context back
  lw_state_t *state = (lw_state_t *)context;

  write_to_tun(state->tun_fd, packet, length);

  return HE_SUCCESS;
}

void on_tun_event(uv_poll_t *handle, int status, int events) {
  // Get our state
  lw_state_t *state = (lw_state_t *)handle->data;
  LW_CHECK_WITH_MSG(state, "State not found on tunnel event");

  // What event did we get? We only care about it becoming readable...
  if((events & UV_READABLE) == UV_READABLE) {
    // Loop over all available packets whilst we're here...
    while(true) {
      // Create sizeof(HE_MAX_MTU)
      // Read in IP packet

      // This needs to be set to a well understood and used variable - no magic numbers...
      uint8_t msg_content[LW_MAX_INSIDE_MTU] = {0};

      // Read a packet
      int length = read_from_tun(handle->io_watcher.fd, msg_content, LW_MAX_INSIDE_MTU);

      // Would have blocked, so all packets are read - we can stop reading now
      if(length == -1) {
        return;
      }

      // Drop packets which exceed the MTU
      if(length > LW_MAX_INSIDE_MTU) {
        // Do nothing, just drop it
        continue;
      }

      switch(he_internal_packet_type(msg_content, length)) {
        case HE_PACKET_IP4: {
          int res = he_conn_inside_packet_received(state->he_conn, msg_content, length);
          if(res != HE_SUCCESS) {
            zlogf_time(ZLOG_INFO_LOG_MSG, "Error returned from libhe for tun packets: %d", res);
          }
          break;  // Out of switch, not the while loop
        }
        case HE_PACKET_IP6:
        case HE_BAD_PACKET:
          break;  // Out of switch, not the while loop
      }
    }
  }
}

void lw_config_tunnel_internal(lw_state_t *state) {
  // Initialise the tun device (the actual device is set up in a Lua helper script, but ideally we
  // should do that natively)
  char tundev[IFNAMSIZ];
  strncpy(tundev, state->tun_name, IFNAMSIZ - 1);
  tundev[IFNAMSIZ - 1] = '\0';

  state->tun_fd = tun_alloc(tundev, IFF_TUN | IFF_NO_PI);

  if(state->tun_fd == -1) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not allocate tun device '%s'\n", tundev);
    zlog_finish();
    LW_EXIT_WITH_FAILURE();
  }

  // Check the tun devices names match - should do but abort if not as the supporting config won't
  // be correct
  if(strncmp(tundev, state->tun_name, IFNAMSIZ)) {
    zlogf_time(ZLOG_INFO_LOG_MSG,
               "Fatal Error: tun device should have been %s but was %s instead!\n", state->tun_name,
               tundev);
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Set up the libuv polling handler
  int res = uv_poll_init(state->loop, &state->uv_tun, state->tun_fd);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Fatal Error: Could not initialise tun interface - %s\n",
               uv_strerror(res));
    zlog_finish();
    exit(EXIT_FAILURE);
  }

  // Note that we currently do NOT set the internal IPs here, we assume this has been set up
  // externally

  // Store state on the tun interface
  state->uv_tun.data = state;
  he_ssl_ctx_set_inside_write_cb(state->he_ctx, tun_write_cb);
}

void configure_tunnel_server(lw_config_t *config, lw_state_t *state) {
  lw_config_tunnel_internal(state);
}

void start_tunnel_server(lw_state_t *state) {
  // Start listening on the tun interface
  uv_poll_start(&state->uv_tun, UV_READABLE, on_tun_event);
}

he_return_code_t network_config_ipv4_cb(he_conn_t *he_conn, he_network_config_ipv4_t *config,
                                        void *context) {
  lw_state_t *state = (lw_state_t *)context;

  zlogf_time(ZLOG_INFO_LOG_MSG, "Received network config Local: %s Peer: %s DNS: %s MTU: %d\n",
             config->local_ip, config->peer_ip, config->dns_ip, config->mtu);

  state->client_ip = config->local_ip;
  state->peer_ip = config->peer_ip;
  state->dns_ip = config->dns_ip;
  state->mtu = config->mtu;

  lw_config_tunnel_internal(state);

  tun_set_ip_internal(state->tun_name, state->client_ip, state->peer_ip, config->mtu);

  uv_poll_start(&state->uv_tun, UV_READABLE, on_tun_event);

  return HE_SUCCESS;
}

void configure_tunnel_client(lw_config_t *config, lw_state_t *state) {
  he_ssl_ctx_set_inside_write_cb(state->he_ctx, tun_write_cb);
  he_ssl_ctx_set_network_config_ipv4_cb(state->he_ctx, network_config_ipv4_cb);
}
