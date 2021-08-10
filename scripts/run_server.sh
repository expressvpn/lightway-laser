#!/usr/bin/env bash

set -e

scripts/setup_nat_tun.sh

build/release/lw.out --server \
  --protocol udp              \
  --username test             \
  --password test             \
  --server_ip '0.0.0.0'       \
  --server_port 19655         \
  --cert certs/shared.crt     \
  --key certs/server.key      \
  --tun helium-test
