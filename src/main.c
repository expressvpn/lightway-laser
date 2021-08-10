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

#include <lw.h>
#include <argparse.h>
#include <stdio.h>
#include <state.h>
#include <util.h>

static const char *const usage[] = {
    "he.out [--server|--client] [options]",
    NULL,
};

int main(int argc, const char **argv) {
  // Initialise logging
  zlog_init_stdout();
  atexit(zlog_finish);

  int server = 0;
  int client = 0;

  lw_config_t config = {0};

  const char *protocol = NULL;

  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_GROUP("Mode options (Mutually Exclusive)"),
      OPT_BOOLEAN(0, "server", &server, "server mode"),
      OPT_BOOLEAN(0, "client", &client, "client mode"),
      OPT_GROUP("Configuration Options"),
      OPT_STRING(0, "username", &config.username, "username"),
      OPT_STRING(0, "password", &config.password, "password"),
      OPT_STRING(0, "server_ip", &config.server_ip, "server ip"),
      OPT_INTEGER(0, "server_port", &config.server_port, "server port"),
      OPT_STRING(0, "protocol", &protocol, "[udp|tcp]"),
      OPT_STRING(0, "cert", &config.crt_path, "path to cert"),
      OPT_STRING(0, "key", &config.server_key_path, "path to server key"),
      OPT_STRING(0, "tun", &config.tun_name, "tun device to use"),
      OPT_END(),
  };

  struct argparse argparse;
  argparse_init(&argparse, options, usage, 0);
  argparse_describe(&argparse, "\nReference client/server for lightway-core.", "");
  argc = argparse_parse(&argparse, argc, argv);

  LW_CHECK_WITH_MSG((!server || !client), "Choose either --server or --client, not both.");
  LW_CHECK_WITH_MSG(server || client, "One of --server or --client is required.");

  if(protocol == NULL) {
    zlogf_time(ZLOG_INFO_LOG_MSG, "--protocol is required.\n");
    zlog_finish();
    LW_EXIT_WITH_FAILURE();

  } else if(0 == strncmp(protocol, "tcp", 3)) {
    config.streaming = true;
  } else if(0 == strncmp(protocol, "udp", 3)) {
    config.streaming = false;
  } else {
    zlogf_time(ZLOG_INFO_LOG_MSG, "Invalid protocol %s must be either udp or tcp\n", protocol);
    zlog_finish();
    LW_EXIT_WITH_FAILURE();
  }

  lw_state_t *state = NULL;

  if(server) {
    state = lw_start_server(&config);
  } else {
    state = lw_start_client(&config);
  }

  // Technically unnecessary since we would have exited at this point if there was a problem, but
  // always good to double-check
  LW_CHECK_WITH_MSG(state, "State returned was null");

  // Ignore sig pipe (shouldn't affect UDP but adding it now so when TCP is added this isn't
  // forgotten)
  signal(SIGPIPE, SIG_IGN);

  // Run the main loop
  return uv_run(state->loop, UV_RUN_DEFAULT);

  return 0;
}
