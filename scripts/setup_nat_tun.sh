#!/usr/bin/env bash
set -e
tunname="helium-test"
subnet="10.125.0.0/16"
wifidev=$(ip route get 8.8.8.8 | grep -P -o 'dev (.*?) ' | cut -d ' ' -f 2)
basenet=$(ip addr show ${wifidev} | grep -P -o "inet (.*?) " | cut -d ' ' -f 2 | cut -d '/' -f 1)
echo "FOUND DEV AND IP ${wifidev} ${basenet}"
gateway=$(ip route get 8.8.8.8 | grep -P -o 'via (.*?) ' | cut -d ' ' -f 2)
echo "FOUND GATEWAY: " ${gateway}

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -s ${subnet} -o ${wifidev} -j SNAT --to ${basenet}

ip tuntap add mode tun dev $tunname
ip link set dev $tunname mtu 1350
ip link set dev $tunname up
ip addr replace 10.125.0.1 peer 10.125.0.2 dev $tunname
ip route replace 10.125.0.0/16 via 10.125.0.2

