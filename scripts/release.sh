#!/usr/bin/env bash
# Build release artefacts for v* tags: linux amd64/arm64 tarballs + checksums.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)}"
OUT="dist/release"
rm -rf "$OUT"
mkdir -p "$OUT"

for arch in amd64 arm64; do
  pkg="$OUT/tamperguard_${VERSION}_linux_${arch}"
  mkdir -p "$pkg"
  for cmd in tg-server tg-agent tg-publish tg-proxy; do
    GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "$pkg/$cmd" "./cmd/$cmd"
  done
  cp LICENSE "$pkg/" 2>/dev/null || true
  tar -C "$OUT" -czf "$pkg.tar.gz" "$(basename "$pkg")"
  rm -rf "$pkg"
  echo "built $pkg.tar.gz"
done

# Windows agent bundle (protect + publish + service installer).
winpkg="$OUT/tamperguard_${VERSION}_windows_amd64"
mkdir -p "$winpkg"
for cmd in tg-agent tg-publish; do
  GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$winpkg/$cmd.exe" "./cmd/$cmd"
done
cp deploy/windows/install-service.ps1 "$winpkg/" 2>/dev/null || true
cp deploy/windows/verify-hardening.ps1 "$winpkg/" 2>/dev/null || true
cp deploy/windows/tg-agent-tray.ps1 "$winpkg/" 2>/dev/null || true
cp deploy/windows/README.md "$winpkg/" 2>/dev/null || true
cp LICENSE "$winpkg/" 2>/dev/null || true
if command -v zip >/dev/null; then
  (cd "$OUT" && zip -qr "$(basename "$winpkg").zip" "$(basename "$winpkg")")
  rm -rf "$winpkg"
else
  tar -C "$OUT" -czf "$winpkg.tar.gz" "$(basename "$winpkg")"
  rm -rf "$winpkg"
fi
echo "built windows amd64 bundle"

cd "$OUT"
sha256sum ./*.tar.gz ./*.zip > SHA256SUMS
cat SHA256SUMS
