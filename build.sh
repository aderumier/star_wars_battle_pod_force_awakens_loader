#!/bin/sh
# Build swpod (replacement hasp_windows_x64_100610.dll).
# Uses mingw-w64 when available (CI), else clang + lld + Wine's PE import libs.
set -e
cd "$(dirname "$0")"
mkdir -p build
OUT=build/hasp_windows_x64_100610.dll
FLAGS="-nostdlib -shared -O2 -Wall -Wno-unused-function -ffreestanding -fno-stack-protector -mno-stack-arg-probe"
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 && [ "$USE_WINE_CLANG" != 1 ]; then
    x86_64-w64-mingw32-gcc $FLAGS -s src/swpod.c src/hasp.def -o $OUT \
        -lkernel32 -luser32 -lmsvcrt -Wl,--entry,DllMain
else
    clang --target=x86_64-w64-windows-gnu -fuse-ld=lld $FLAGS \
        -I/usr/include/wine/windows -I/usr/include/wine/msvcrt \
        src/swpod.c src/hasp.def -o $OUT \
        -L/usr/lib/wine/x86_64-windows -lkernel32 -luser32 -lmsvcrt \
        -Wl,--entry,DllMain
fi
echo built $OUT
