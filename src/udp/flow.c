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

#include "flow.h"
#include "util.h"
#include "state.h"

typedef struct send_req {
  uv_udp_send_t req;
  uv_buf_t buf;
} send_req_t;

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  // Allocate the buffer
  buf->base = calloc(1, suggested_size);
  LW_CHECK_WITH_MSG(buf->base, "Unable to allocate buffer for incoming data");
  // Set the size
  buf->len = suggested_size;
}

void on_read(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr,
             unsigned flags) {
  LW_CHECK_WITH_MSG(handle, "Impossible state occurred, handle was null in on_read!");

  // Negative reads are socket errors indicating recvmsg failed
  if(nread < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Read Error on UDP socket: %s\n", uv_err_name(nread));
    goto cleanup;
  }

  if(nread <= sizeof(he_wire_hdr_t)) {
    // Noise
    goto cleanup;
  }

  if(buf == NULL) {
    // Should be impossible
    goto cleanup;
  }

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)buf->base;
  if(hdr->he[0] != 'H' || hdr->he[1] != 'e') {
    goto cleanup;
  }

  uint64_t session = hdr->session;

  lw_state_t *state = (lw_state_t *)handle->data;

  if(state->is_server) {
    if(state->he_conn == NULL && session == HE_PACKET_SESSION_EMPTY) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Creating connection\n");
      lw_state_server_connect(state, addr);
      zlogf_time(ZLOG_INFO_LOG_MSG, "Created with session %x\n", state->session);
    } else if(state->he_conn == NULL && session != HE_PACKET_SESSION_EMPTY) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Rejecting session!!\n");
      he_session_reject(state, addr);
      goto cleanup;
    } else if(state->he_conn != NULL && session == HE_PACKET_SESSION_EMPTY) {
      // TODO Can't reconnect here :-/
    }

    if(state->he_conn == NULL) {
      zlogf_time(ZLOG_INFO_LOG_MSG, "Unable to connect");
      goto cleanup;
    }

    // We don't support non-IP4 connections here so we'll just cast and assume it works
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;

    // Check for change of address
    if(state->send_addr.sin_addr.s_addr != addr_in->sin_addr.s_addr ||
       state->send_addr.sin_port != addr_in->sin_port) {
      if(session == state->session) {
        // Copy in the client's IP address
        memcpy(&state->send_addr, addr, sizeof(struct sockaddr));
      } else {
        he_session_reject(state, addr);
        goto cleanup;
      }
    }
  } else {
    LW_CHECK_WITH_MSG(state->he_conn, "Client should not exist without initialised he_conn");
  }

  he_return_code_t res = he_conn_outside_data_received(state->he_conn, (uint8_t *)buf->base, nread);

  if(res != HE_SUCCESS) {
    bool fatal = he_conn_is_error_fatal(state->he_conn, res);
    zlogf_time(ZLOG_INFO_LOG_MSG, "Non-zero return code from libhelium: %s Fatal?: %s", he_return_code_name(res),
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

void on_send(uv_udp_send_t *req, int status) {
  send_req_t *send_req = (send_req_t *)req;
  free(send_req->buf.base);
  free(send_req);
}

he_return_code_t udp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context) {
  // Get our context back
  lw_state_t *state = (lw_state_t *)context;

  send_req_t *req = (send_req_t *)calloc(1, sizeof(send_req_t));
  LW_CHECK_WITH_MSG(req, "Unable to allocate write request!");

  uint8_t *output_buffer = calloc(1, LW_MAX_WIRE_MTU);
  LW_CHECK_WITH_MSG(output_buffer, "Unable to allocate write buffer");
  memcpy(output_buffer, packet, length);

  req->buf = uv_buf_init((char *)output_buffer, (unsigned int)length);

  int res = uv_udp_send((uv_udp_send_t *)req, &state->udp_socket, &req->buf, 1,
                        (const struct sockaddr *)&state->send_addr, on_send);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_write: %s (%d)\n", uv_strerror(res),
               res);
    return HE_ERR_CALLBACK_FAILED;
  }

  return HE_SUCCESS;
}

void he_session_reject(lw_state_t *state, const struct sockaddr *addr) {
  // TODO Normalise this with above

  // Session Error identifier
  uint64_t error = HE_PACKET_SESSION_REJECT;

  // Allocate send request
  send_req_t *req = (send_req_t *)calloc(1, sizeof(send_req_t));
  LW_CHECK_WITH_MSG(req, "Unable to allocate request");

  // Allocate buffer
  char *write_buf = (char *)calloc(1, sizeof(he_wire_hdr_t));
  LW_CHECK_WITH_MSG(write_buf, "Unable to allocate write_buf");

  he_wire_hdr_t *hdr = (he_wire_hdr_t *)write_buf;

  hdr->he[0] = 'H';
  hdr->he[1] = 'e';

  hdr->major_version = 1;
  hdr->minor_version = 0;

  // Memcpy in the session identifier
  memcpy(&hdr->session, &error, sizeof(uint64_t));

  // Initialise the write buffer
  req->buf = uv_buf_init(write_buf, sizeof(he_wire_hdr_t));

  // Write it out
  int err = uv_udp_send((uv_udp_send_t *)req, &state->udp_socket, &req->buf, 1, addr, on_send);

  if(err) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during session reject on uv_udp_send: %d\n", err);
  }
}
