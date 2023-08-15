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

#ifndef LW_FLOW_H
#define LW_FLOW_H

#include <lw.h>

void alloc_tcp_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);

he_return_code_t tcp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context);

#endif  // LW_FLOW_H
