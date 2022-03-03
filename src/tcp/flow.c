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

typedef struct {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;


void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  // Allocate the buffer
  buf->base = calloc(1, suggested_size);
  LW_CHECK_WITH_MSG(buf->base, "Unable to allocate buffer for incoming data");
  // Set the size
  buf->len = suggested_size;
}

void on_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
  LW_CHECK_WITH_MSG(handle, "Impossible state occurred, handle was null in on_read!");

  // Negative reads are socket errors indicating recvmsg failed
  if(nread < 0) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Read Error on TCP socket: %s\n", uv_err_name(nread));
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

  //TODO add addr
  struct sockaddr *addr;

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
    zlogf_time(ZLOG_INFO_LOG_MSG, "Non-zero return code from libhelium: %d Fatal?: %s", res,
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

/* Send call back to free buffer; used with tcp_send */
void on_send(uv_write_t* req, int status) {
  write_req_t *write_req = (write_req_t *)req;
  free(write_req->buf.base);
  free(write_req);
}

he_return_code_t tcp_write_cb(he_conn_t *he_conn, uint8_t *packet, size_t length, void *context) {
  // Get our context back
  lw_state_t *state = (lw_state_t *)context;

  write_req_t *req = (write_req_t *)calloc(1, sizeof(write_req_t));
  LW_CHECK_WITH_MSG(req, "Unable to allocate write request!");

  uint8_t *output_buffer = calloc(1, LW_MAX_WIRE_MTU);
  LW_CHECK_WITH_MSG(output_buffer, "Unable to allocate write buffer");
  memcpy(output_buffer, packet, length);

  req->buf = uv_buf_init((char *)output_buffer, (unsigned int)length);

  int res = uv_write((uv_write_t *)req,(uv_stream_t *)&state->tcp_socket, &req->buf, 1, on_send);

  if(res) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during uv_write: %s (%d)\n", uv_strerror(res),
               res);
    return HE_ERR_CALLBACK_FAILED;
  }

  return HE_SUCCESS;
}


/* callback if a tcp client connects to server*/
void on_connect(uv_connect_t* connection, int status) {
  /* Implement on connect */
  uv_stream_t* stream = connection->handle;
  int res = uv_read_start(stream, alloc_buffer, on_read);
  LW_CHECK_WITH_MSG(res == 0, "Unable to recv on tcp socket");
}

/* Callback if a new connection arrives */
void on_new_connection(uv_stream_t *server, int status) {
  if(status < 0){
    zlogf_time(ZLOG_INFO_LOG_MSG, "New connection error %s\n", uv_strerror(status));
    return ;
  }

  /* Create a new client socket */
  uv_tcp_t *client = calloc(1,sizeof(uv_tcp_t));
  int res = uv_tcp_init(server->loop,client);
  LW_CHECK_WITH_MSG(res == 0, "Unable to initialise Client Socket");

/* Accept the client */
  res = uv_accept(server, (uv_stream_t *) client);
  LW_CHECK_WITH_MSG(res == 0, "Unable to accept the client");

/* Read from the client socket */
  res = uv_read_start((uv_stream_t *) client,alloc_buffer,on_read);
  LW_CHECK_WITH_MSG(res == 0, "Unable to read from client socket");

}

/* Callback after data is read */
void he_session_reject(lw_state_t *state, const struct sockaddr *addr) {
  // TODO Normalise this with above

  // Session Error identifier
  uint64_t error = HE_PACKET_SESSION_REJECT;

  // Allocate send request
  write_req_t* req = (write_req_t *)calloc(1, sizeof(write_req_t));
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

  int err = uv_write((uv_write_t *)req,(uv_stream_t *) &state->tcp_socket, &req->buf, 1, on_send);

  if(err) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Error occurred during session reject on uv_write: %d\n", err);
  }
}
