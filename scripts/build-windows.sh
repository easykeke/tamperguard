#!/usr/bin/env bash
# Build the Windows binaries (cross-compiled from Linux/WSL).
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
OUT="${OUT:-dist/windows}"
mkdir -p "$OUT"
for cmd in tg-server tg-agent tg-publish; do
  GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT/$cmd.exe" "./cmd/$cmd"
  echo "built $OUT/$cmd.exe"
done
