#!/bin/sh
# Run Star Wars Battle Pod without TeknoParrot (swpod must be installed).
GAME="${GAME:-/home/aderumier/code/jurassicpark.wine/drive_c/game/Star Wars Battle Pod - The Force Awakens}"
export WINEPREFIX="${WINEPREFIX:-/home/aderumier/code/jurassicpark.wine}"
cd "$GAME/Launcher" && exec wine RSLauncher.exe "$@"
