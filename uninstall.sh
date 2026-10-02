#!/bin/sh
# Restore the original HASP DLLs (needed to run the game through TeknoParrot again).
GAME="${GAME:-/home/aderumier/code/jurassicpark.wine/drive_c/game/Star Wars Battle Pod - The Force Awakens}"
DLL=hasp_windows_x64_100610.dll
for d in "$GAME/Launcher" "$GAME/Binaries/Win64"; do
    [ -f "$d/$DLL.orig" ] && cp "$d/$DLL.orig" "$d/$DLL"
done
echo restored
