#!/bin/sh
# Run Star Wars Battle Pod without TeknoParrot (swpod must be installed).
GAME="${GAME:-/home/aderumier/code/jurassicpark.wine/drive_c/game/Star Wars Battle Pod - The Force Awakens}"
export WINEPREFIX="${WINEPREFIX:-/home/aderumier/code/jurassicpark.wine}"
export WINEDLLOVERRIDES="d3d9,d3d11,dxgi,d3d10core=n,b${WINEDLLOVERRIDES:+;$WINEDLLOVERRIDES}"
cd "$GAME/Launcher" && exec wine RSLauncher.exe "$@"
