#!/usr/bin/env bash
# End-to-end test of the Landlock process self-protection layer.
#
# Proves that a web-like process started through `tg-agent landlock` cannot
# overwrite, create or delete files outside its write allow-list, while normal
# reads and writes inside the allow-list keep working. This is independent of
# the eBPF backend: it protects the process itself, so a compromised web server
# cannot rewrite the document root even if the kernel has no bpf LSM.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
BASE=/tmp/tg-e2e-landlock
SITE=/srv/tg-landlock-site
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() { rm -rf "$BASE" "$SITE"; }
trap cleanup EXIT

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "kernel support"
if ! "$BIN/tg-agent" landlock --check; then
  echo "E2E (landlock) SKIP: kernel has no Landlock support"
  exit 0
fi
ok "landlock available"

say "fixtures"
rm -rf "$BASE" "$SITE"
mkdir -p "$BASE/writable" "$SITE"
printf '<html>original</html>\n' > "$SITE/index.html"
printf 'allowed\n' > "$BASE/writable/fill.txt"
ok "site at $SITE, writable dir at $BASE/writable"

say "confined process cannot modify the protected tree"
# --no-defaults so /tmp is not implicitly writable (the site lives elsewhere,
# but the test should not depend on that).
if "$BIN/tg-agent" landlock --no-defaults --allow-write "$BASE/writable" -- \
     sh -c "echo evil > '$SITE/index.html'" 2>"$BASE/err1"; then
  bad "overwrite of protected file was allowed"
else
  ok "overwrite denied (exit $?)"
fi
grep -qi 'permission denied' "$BASE/err1" && ok "denial surfaced as EACCES" || { cat "$BASE/err1"; bad "unexpected error"; }
[ "$(cat "$SITE/index.html")" = "<html>original</html>" ] && ok "protected content unchanged" || bad "content changed"

if "$BIN/tg-agent" landlock --no-defaults --allow-write "$BASE/writable" -- \
     sh -c "echo evil > '$SITE/new.html'" 2>/dev/null; then
  bad "creation of a new file in the protected tree was allowed"
else
  ok "creation denied"
fi
[ ! -e "$SITE/new.html" ] && ok "no new file on disk" || bad "new file landed"

if "$BIN/tg-agent" landlock --no-defaults --allow-write "$BASE/writable" -- \
     rm -f "$SITE/index.html" 2>/dev/null; then
  bad "deletion of a protected file was allowed"
else
  ok "deletion denied"
fi
[ -e "$SITE/index.html" ] && ok "file still present" || bad "file was deleted"

say "reads and allow-listed writes still work"
OUT=$( "$BIN/tg-agent" landlock --no-defaults --allow-write "$BASE/writable" -- \
  cat "$SITE/index.html" ) && echo "$OUT" | grep -q original && ok "read allowed" || bad "read blocked"
"$BIN/tg-agent" landlock --no-defaults --allow-write "$BASE/writable" -- \
  sh -c "echo ok > '$BASE/writable/inside.txt'" && [ -f "$BASE/writable/inside.txt" ] \
  && ok "write inside the allow-list allowed" || bad "allow-listed write failed"

say "standard devices are writable with the default allow-list"
# The wrapper must not break normal runtimes: /dev/null and friends are allowed
# by default (a write-open on a device is a write-class operation for Landlock).
"$BIN/tg-agent" landlock --allow-write "$BASE/writable" -- \
  sh -c "echo discard > /dev/null" && ok "default allow-list permits /dev/null" || bad "/dev/null blocked by defaults"

say "compromised runtime (Node.js) cannot write the site"
if command -v node >/dev/null; then
  if "$BIN/tg-agent" landlock --no-defaults --allow-write "$BASE/writable" -- \
       node -e "require('fs').writeFileSync(process.argv[1], 'evil')" "$SITE/index.html" 2>/dev/null; then
    bad "node wrote the protected file under landlock"
  else
    ok "node write blocked inside the sandbox"
  fi
  [ "$(cat "$SITE/index.html")" = "<html>original</html>" ] && ok "content still unchanged" || bad "content changed by node"
else
  ok "node not installed, skipping runtime demonstration"
fi

say "control: without the wrapper the same write succeeds"
printf '<html>original</html>\n' > "$SITE/index.html"
sh -c "echo evil > '$SITE/index.html'" && grep -q evil "$SITE/index.html" && ok "unprotected write succeeds (as expected)" || bad "control write failed"

say "probe reports the sandbox capability"
"$BIN/tg-agent" probe --state-dir "$BASE/agent" 2>&1 | grep -q "landlock" && ok "probe shows landlock" || bad "probe does not mention landlock"

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (landlock) PASS"; else echo "E2E (landlock) FAILED"; fi
exit "$FAIL"
