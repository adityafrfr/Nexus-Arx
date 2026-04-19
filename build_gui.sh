#!/bin/bash
set -e

echo "=== Building Nexus-ARX-T (Backend + GUI) ==="

# Check for required tooling
if ! command -v pkg-config &> /dev/null; then
    echo "Error: pkg-config is required."
    exit 1
fi

if ! command -v nasm &> /dev/null; then
    echo "Error: nasm is required."
    exit 1
fi

echo "[1/4] Building ARX Assembly core ..."
nasm -f elf64 nexus_arx_core.asm -o nexus_arx_core.o

echo "[2/4] Compiling C crypto driver ..."
gcc -O3 -DNDEBUG -c nexus_arx_t.c -o nexus_arx_t.o $(pkg-config --cflags openssl)
gcc -O3 nexus_arx_t.o nexus_arx_core.o -o nexus_arx_t $(pkg-config --libs openssl)
echo " -> Success! Executable created: ./nexus_arx_t"

echo "[3/4] Compiling Linux GUI (GTK3) ..."
gcc gui.c -o xor_gui_linux $(pkg-config --cflags --libs gtk+-3.0)

if [ $? -eq 0 ]; then
    echo " -> Success! Executable created: ./xor_gui_linux"
else
    echo " -> Linux build failed. Ensure 'libgtk-3-dev' is installed."
    exit 1
fi

echo ""
echo "[4/4] Attempting to cross-compile GUI for Windows (MinGW) ..."
if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    x86_64-w64-mingw32-gcc gui.c -o xor_gui_windows.exe -mwindows -lcomdlg32
    if [ $? -eq 0 ]; then
        echo " -> Success! Executable created: xor_gui_windows.exe"
        echo " -> Note: Windows backend build is not included in this Linux helper."
    else
        echo " -> Windows build failed."
    fi
else
    echo " -> x86_64-w64-mingw32-gcc not found. Skipping Windows cross-compilation."
    echo "    (Install mingw-w64 if you want to build the Windows version from Linux)."
fi
