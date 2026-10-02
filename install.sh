#!/bin/sh
# Install swpod into the game: back up the real HASP DLLs once, copy ours over them.
set -e
GAME="${GAME:-/home/aderumier/code/jurassicpark.wine/drive_c/game/Star Wars Battle Pod - The Force Awakens}"
DLL=hasp_windows_x64_100610.dll
for d in "$GAME/Launcher" "$GAME/Binaries/Win64"; do
    [ -f "$d/$DLL.orig" ] || cp "$d/$DLL" "$d/$DLL.orig"
    cp "$(dirname "$0")/build/$DLL" "$d/$DLL"
done
[ -f "$GAME/swpod.ini" ] || cp "$(dirname "$0")/swpod.ini" "$GAME/swpod.ini"
echo installed
