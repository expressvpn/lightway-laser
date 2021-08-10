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

#ifndef LIBHE_TESTABLE_TYPES
#define LIBHE_TESTABLE_TYPES

typedef struct he_client {
  int id;
} he_client_t;

typedef struct he_ssl_ctx_config {
  int id;
} he_ssl_ctx_config_t;

typedef struct he_ssl_ctx {
  int id;
} he_ssl_ctx_t;

typedef struct he_conn_config {
  int id;
} he_conn_config_t;

typedef struct he_conn {
  int id;
} he_conn_t;

typedef struct he_plugin_chain {
  int id;
} he_plugin_chain_t;

#endif
