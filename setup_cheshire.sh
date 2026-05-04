#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AX_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ax) AX_DIR="$2"; shift 2 ;;
        *) echo "Usage: $0 --ax <AdaptixC2-dir>"; exit 1 ;;
    esac
done

if [[ -z "$AX_DIR" ]]; then
    echo "Usage: $0 --ax <AdaptixC2-dir>"
    exit 1
fi

AX_DIR="$(realpath "$AX_DIR")"
SRC_DIR="$AX_DIR/AdaptixServer/extenders/cheshire_service"
DIST_DIR="$AX_DIR/dist/extenders/cheshire_service"
GOWORK="$AX_DIR/AdaptixServer/go.work"

echo "[*] Copying source to AdaptixServer/extenders..."
rm -rf "$SRC_DIR"
mkdir -p "$SRC_DIR"
cp -r "$SCRIPT_DIR/cheshire_service/"* "$SRC_DIR/"

echo "[*] Adding to Go workspace..."
if [ -f "$GOWORK" ]; then
    if ! grep -q "extenders/cheshire_service" "$GOWORK"; then
        cd "$AX_DIR/AdaptixServer"
        go work use ./extenders/cheshire_service
        go work sync
    fi
fi

echo "[*] Building..."
cd "$SRC_DIR"
make all

echo "[*] Deploying to dist..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"
cp -r "$SRC_DIR/dist/"* "$DIST_DIR/"

echo "[+] Cheshire deployed to $DIST_DIR"
echo "    Restart the Adaptix server — 'Test with Cheshire' will appear in the Sessions menu."
