#!/bin/bash
set -e

echo "[1/3] Building backend..."
nasm -f elf64 nexus_arx_core.asm -o nexus_arx_core.o
gcc -O3 -DNDEBUG -c nexus_arx_t.c -o nexus_arx_t.o $(pkg-config --cflags openssl)
gcc -O3 nexus_arx_t.o nexus_arx_core.o -o nexus_arx_t $(pkg-config --libs openssl)

echo "[2/3] Building GUI..."
gcc gui.c -o xor_gui_linux $(pkg-config --cflags --libs gtk+-3.0)

echo "[3/3] Launching GUI..."
./xor_gui_linux
