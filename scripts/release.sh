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
  for cmd in tg-server tg-agent tg-publish; do
    GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w" -o "$pkg/$cmd" "./cmd/$cmd"
  done
  cp LICENSE "$pkg/" 2>/dev/null || true
  tar -C "$OUT" -czf "$pkg.tar.gz" "$(basename "$pkg")"
  rm -rf "$pkg"
  echo "built $pkg.tar.gz"
done

cd "$OUT"
sha256sum ./*.tar.gz > SHA256SUMS
cat SHA256SUMS
