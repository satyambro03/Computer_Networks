# Bouncer 2.0 (trafficcop) - eBPF/XDP Firewall

An in-kernel eBPF/XDP edge packet filter and control daemon built for the Low-Level Hackathon (CN01).

## How It Works
- Kernel Data Path (src/trafficcop_xdp.c): Intercepts packets at the XDP hook before sk_buff allocation. Parses Ethernet, 802.1Q VLAN tags, IPv4 headers (with variable IHL/options), and L4 TCP/UDP/ICMP headers. Enforces token-bucket rate limits, dynamic source jails, packet bouncing (XDP_TX), and rules matching.
- Control Plane (src/main.c): Validates .rules files, loads BPF maps, supports zero-downtime hot reloads (trafficcop reload), manages live jails (jail/unjail), and serves a real-time dashboard on http://127.0.0.1:8088/ and /stats.json.

## Required APT Packages (Ubuntu 24.04)
- clang
- llvm
- libbpf-dev
- linux-headers-$(uname -r)
- gcc
- make
- iproute2
- gcc-multilib
- lib32z1-dev

## Build & Run
./build.sh
sudo ./trafficcop start <ifname> <rules_file>

## How We Tested It
Run the automated network namespace and veth test bench:
sudo ./bench.sh
