#!/usr/bin/env bash
# End-to-end check of the fs-verity hardening layer.
#
# fs-verity needs CONFIG_FS_VERITY in the kernel and a filesystem created with
# the "verity" feature (ext4/f2fs/btrfs). The WSL2 kernel used during
# development has CONFIG_FS_VERITY unset, so this script skips cleanly there;
# on a distribution kernel it verifies that a published file becomes read-only
# and gets a stable digest.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
BASE=/var/tmp/tg-e2e-verity
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }
cleanup() { rm -rf "$BASE"; }
trap cleanup EXIT

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "kernel/filesystem support"
mkdir -p "$BASE"
PROBE=$("$BIN/tg-agent" probe --state-dir "$BASE" 2>&1 | grep 'fs-verity' || true)
echo "  $PROBE"
if echo "$PROBE" | grep -q 'unavailable'; then
  echo "E2E (verity) SKIP: this kernel/filesystem has no fs-verity support"
  exit 0
fi
ok "fs-verity available"

say "enable verity on a published file"
printf '<html>verified</html>\n' > "$BASE/index.html"
"$BIN/tg-agent" verity enable "$BASE/index.html" || bad "enable failed"
"$BIN/tg-agent" verity check "$BASE/index.html" | grep -q 'verity=true' && ok "file is a verity file" || bad "check says not verity"

say "verity file is read-only"
if ( echo evil > "$BASE/index.html" ) 2>"$BASE/err"; then
  bad "a verity file accepted a write"
else
  ok "write rejected (as designed)"
fi
grep -qi 'permission denied\|operation not permitted' "$BASE/err" && ok "rejection is a permission error" || { cat "$BASE/err"; bad "unexpected error"; }
[ "$(cat "$BASE/index.html")" = "<html>verified</html>" ] && ok "content unchanged" || bad "content changed"

say "digest is stable and well formed"
D1=$("$BIN/tg-agent" verity digest "$BASE/index.html")
D2=$("$BIN/tg-agent" verity digest "$BASE/index.html")
[ "${#D1}" -eq 64 ] && ok "digest is 64 hex chars" || bad "digest length ${#D1}"
[ "$D1" = "$D2" ] && ok "digest is stable" || bad "digest changed between reads"

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (verity) PASS"; else echo "E2E (verity) FAILED"; fi
exit "$FAIL"
