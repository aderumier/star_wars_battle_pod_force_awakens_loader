#!/bin/sh
# Make a release zip laid out like the game directory:
#   Launcher/ and Binaries/Win64/ get the loader DLL, Binaries/Win64/ the DXVK DLLs,
#   the root swpod.ini + run.sh. Usage: package.sh [version]
set -e
cd "$(dirname "$0")"
VER="${1:-dev}"
NAME="swpod-$VER"
STAGE="build/$NAME"
rm -rf "$STAGE" "build/$NAME.zip"
mkdir -p "$STAGE/Launcher" "$STAGE/Binaries/Win64"
cp build/hasp_windows_x64_100610.dll "$STAGE/Launcher/"
cp build/hasp_windows_x64_100610.dll "$STAGE/Binaries/Win64/"
cp dxvk/*.dll "$STAGE/Binaries/Win64/"
cp swpod.ini "$STAGE/"
cat > "$STAGE/run.sh" <<'RUN'
#!/bin/sh
# Run from the game root dir: WINEPREFIX=... ./run.sh
cd "$(dirname "$0")/Launcher"
export WINEDLLOVERRIDES="d3d9,d3d11,dxgi,d3d10core=n,b${WINEDLLOVERRIDES:+;$WINEDLLOVERRIDES}"
exec wine RSLauncher.exe "$@"
RUN
chmod +x "$STAGE/run.sh"
cat > "$STAGE/README.txt" <<'TXT'
swpod - standalone loader for Star Wars Battle Pod: The Force Awakens (ES3X)

Install: back up Launcher/ and Binaries/Win64/hasp_windows_x64_100610.dll, then
extract this archive over the game directory (it replaces both copies of that DLL
and adds DXVK next to the game exe). Settings and controls: swpod.ini.
Run: WINEPREFIX=/path/to/prefix ./run.sh   (on Windows: run Launcher\RSLauncher.exe)
Log: swpod.log in the game directory.
TXT
(cd "$STAGE" && zip -qr "../$NAME.zip" .)
echo "build/$NAME.zip"
