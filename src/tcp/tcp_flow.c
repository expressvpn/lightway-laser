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

#include "tcp_flow.h"
#include "util.h"
#include "state.h"

typedef struct write_req {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;

void alloc_tcp_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  // Allocate the buffer
  buf->base = calloc(1, suggested_size);
  LW_CHECK_WITH_MSG(buf->base, "Unable to allocate buffer for incoming data");
  // Set the size
  buf->len = suggested_size;
}

void on_tcp_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
  LW_CHECK_WITH_MSG(client, "Impossible state occurred, client was null in on_tcp_read!");
  LW_CHECK_WITH_MSG(buf, "Impossible state occurred, buf was null in on_tcp_read!");

  // Negative reads are socket errors indicating recvmsg failed
  if(nread < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Read Error on TCP socket: %s\n", uv_err_name(nread));
    goto cleanup;
  }
  lw_state_t *state = (lw_state_t *)client->data;

  he_return_code_t res = he_conn_outside_data_received(state->he_conn, (uint8_t *)buf->base, nread);

  if(res != HE_SUCCESS) {
    bool fatal = he_conn_is_error_fatal(state->he_conn, res);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Non-zero return code from libhelium: %s Fatal?: %s\n", he_return_code_name(res),
               fatal ? "true" : "false");
    if(fatal) {
      lw_state_disconnect(state);
    }
    goto cleanup;
  }

cleanup:
  if(buf) {
    free(buf->base);
  }

  return;
}

void on_tcp_send(uv_write_t *req, int status) {
  write_req_t *send_req = (write_req_t *)req;
  free(send_req->buf.base);
  free(send_req);
}

he_return_code_t tcp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context) {
  // Get our context back
  lw_state_t *state = (lw_state_t *)context;

  uv_stream_t *stream;

  if (state->is_server) {
    stream = &state->tcp_client;
  } else {
    stream = state->tcp_connect.handle;
  }

  if (stream == NULL) {
    return HE_ERR_NULL_POINTER;
  }

  write_req_t *req = (write_req_t *)calloc(1, sizeof(write_req_t));
  LW_CHECK_WITH_MSG(req, "Unable to allocate write request!");

  uint8_t *output_buffer = calloc(1, LW_MAX_WIRE_MTU);
  LW_CHECK_WITH_MSG(output_buffer, "Unable to allocate write buffer");
  memcpy(output_buffer, packet, length);

  req->buf = uv_buf_init((char *)output_buffer, (unsigned int)length);

  int res = uv_write((uv_write_t *)req, stream, &req->buf, 1, on_tcp_send);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_write: %s (%d)\n", uv_strerror(res),
               res);
    return HE_ERR_CALLBACK_FAILED;
  }

  return HE_SUCCESS;
}
