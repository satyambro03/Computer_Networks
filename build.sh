#!/bin/bash
set -e

if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq clang llvm libbpf-dev linux-headers-$(uname -r) gcc make iproute2 gcc-multilib lib32z1-dev
fi

clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include \
    -I/usr/include/x86_64-linux-gnu \
    -c src/trafficcop_xdp.c -o trafficcop_xdp.o

gcc -O2 src/main.c -lbpf -lelf -lz -lpthread -o trafficcop
chmod +x trafficcop
echo "Build complete: ./trafficcop ready!"
