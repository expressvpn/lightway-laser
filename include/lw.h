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

#ifndef LW_H
#define LW_H

#include <he.h>
#include <uv.h>

#define LW_MAX_WIRE_MTU 1500
#define LW_MAX_INSIDE_MTU 1350

typedef struct lw_config {
  // Username
  char *username;
  // Password
  char *password;
  // Server IP
  char *server_ip;
  // Server Port
  int server_port;
  // Streaming Mode
  bool streaming;
  // Tun device name
  char *tun_name;
  // Server Cert
  char *crt_path;
  // Server Key
  char *server_key_path;
} lw_config_t;

typedef struct lw_state {
  // Shared uv_loop
  uv_loop_t *loop;

  // Mutually exclusive, one or the other will be NULL based on connection_type
  uv_udp_t udp_socket;
  uv_tcp_t tcp_socket;

  // Connection Information
  // UDP Send addr
  struct sockaddr_in send_addr;
  // UDP Session ID
  uint64_t session;

  // Helium Data
  he_ssl_ctx_t *he_ctx;
  he_conn_t *he_conn;
  uv_timer_t he_timer;

  // Homogeneous client IP
  // We cache as str and u32 for
  // different procedures
  char const *client_ip;
  uint32_t client_ip_u32;

  // Client's local IP
  char const *local_ip;
  // Homogenous peer IP
  char const *peer_ip;
  // Homogenous DNS ip
  char const *dns_ip;
  int mtu;

  //TCP Client socket
  uv_connect_t tcp_connect;
  uv_tcp_t tcp_client;

  // The external IP viewable to the outside world
  uint32_t assigned_ip;

  // Auth pieces
  char username[HE_CONFIG_TEXT_FIELD_LENGTH];
  char password[HE_CONFIG_TEXT_FIELD_LENGTH];

  // Tun FD
  int tun_fd;
  uv_poll_t uv_tun;
  char tun_name[HE_CONFIG_TEXT_FIELD_LENGTH];

  // Server or not -- most things don't actually care but some do
  bool is_server;
  // is streaming
  bool is_streaming;

} lw_state_t;

#endif  // LW_H
