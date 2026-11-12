#!/bin/bash
set -e

sudo ip netns del arcade 2>/dev/null || true
sudo ip link del players 2>/dev/null || true

sudo ip netns add arcade
sudo ip link add players type veth peer name eth0 netns arcade
sudo ip addr add 10.0.0.2/24 dev players
sudo ip link set players up

sudo ip -n arcade addr add 10.0.0.1/24 dev eth0
sudo ip -n arcade link set eth0 up
sudo ip -n arcade link set lo up

echo "[*] Starting trafficcop..."
sudo nsenter --net=/run/netns/arcade ./trafficcop start eth0 rules/pixel-arcade.rules

echo "[*] Sending 4 Pings (2 should PASS, 2 should DROP due to rate limit)..."
ping -c 4 -i 0.1 10.0.0.1 -W 1 || true

echo "[*] Live Stats JSON:"
sudo nsenter --net=/run/netns/arcade ./trafficcop stats

echo "[*] Stopping trafficcop..."
sudo nsenter --net=/run/netns/arcade ./trafficcop stop
sudo ip netns del arcade
echo "[*] Success!"
