#!/bin/sh
# Build swpod (replacement hasp_windows_x64_100610.dll) with clang + Wine's PE import libs.
set -e
cd "$(dirname "$0")"
mkdir -p build
clang --target=x86_64-w64-windows-gnu -fuse-ld=lld -nostdlib -shared -O2 -Wall -Wno-unused-function \
    -ffreestanding -fno-stack-protector -mno-stack-arg-probe \
    -I/usr/include/wine/windows -I/usr/include/wine/msvcrt \
    src/swpod.c src/hasp.def -o build/hasp_windows_x64_100610.dll \
    -L/usr/lib/wine/x86_64-windows -lkernel32 -luser32 -lmsvcrt \
    -Wl,--entry,DllMain
echo built build/hasp_windows_x64_100610.dll
