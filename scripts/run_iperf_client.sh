#!/usr/bin/env bash

set -e

SERVER=$(dig +short server)
TARGET=$(dig +short iperf)

echo "Resolved to target ${TARGET} server ${SERVER}"

echo "Check that we have connectivity to the lightway server"
ping -w1 "${SERVER}"

build/release/lw.out --client --protocol tcp --username test --password test --server_ip ${SERVER} --server_port 19655 --cert certs/shared.crt --tun helium-test &

sleep 2

echo "Setting route to ${TARGET} via ${HELIUM_GATE}"
ip route add "${TARGET}" via "${HELIUM_GATE}"

sleep 2

echo "Route to target"
ip route get ${TARGET}

echo "Pinging ${TARGET} a little bit to make sure we're routed"
ping -w3 ${TARGET}

echo "Beginning iperf test"
iperf3 -t 60 -c ${TARGET}

echo "Beginning iperf reverse test"
iperf3 -t 60 -c ${TARGET} -R

kill %1
