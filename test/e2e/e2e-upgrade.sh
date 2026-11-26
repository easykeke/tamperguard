#!/usr/bin/env bash
# End-to-end test of the signed self-upgrade channel.
#
# Proves:
#   1. a tampered artefact (hash does not match the signed manifest) is rejected
#      and the running binary is left untouched
#   2. a correctly signed release is downloaded, verified and swapped in
#   3. the agent exits 0 with a "restart required" signal so systemd restarts it
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-up
PORT=18447
BASE="https://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  pkill -f "agent-under-test run" 2>/dev/null || true
  wait 2>/dev/null
}
trap cleanup EXIT

say "build"
cd "$REPO" || exit 1
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  [ -x "$BIN/tg-server" ] || { echo "prebuilt binaries missing"; exit 1; }
  ok "using prebuilt binaries"
else
  go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
fi
ok "binaries built"

say "control plane"
rm -rf "$DATA"
mkdir -p "$DATA"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; tail -5 "$DATA/server.log"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/agent" --poll 60 > "$DATA/enroll.log" 2>&1 && ok "agent enrolled" || { cat "$DATA/enroll.log"; bad "enroll"; }

say "publish a release"
printf 'upgraded-agent-binary-v9.9.9\n' > "$DATA/release.bin"
"$BIN/tg-server" release --data-dir "$DATA" --binary "$DATA/release.bin" \
  --version 9.9.9 --os linux --arch amd64 > "$DATA/release.out" 2>&1 && ok "release 9.9.9 published" || { cat "$DATA/release.out"; bad "release publish"; }
grep -q '"signature"' "$DATA/release.out" && ok "manifest signed" || bad "manifest has no signature"

# The binary that will be replaced by the upgrade.
cp "$BIN/tg-agent" "$DATA/agent-under-test"
BEFORE_SUM=$(sha256sum "$DATA/agent-under-test" | awk '{print $1}')

say "tampered artefact must be rejected"
ART="$DATA/releases/9.9.9/tg-agent-linux-amd64"
cp "$ART" "$DATA/artefact.good"
# Same length as the real artefact, different bytes: exercises the hash check
# rather than the cheaper size check.
printf 'tampered-agent-binary-v9.9.9\n' > "$ART"
timeout 6 "$DATA/agent-under-test" run --state-dir "$DATA/agent" --enforcer observe \
  --auto-upgrade --upgrade-interval 1s > "$DATA/agent-tampered.log" 2>&1
AFTER_SUM=$(sha256sum "$DATA/agent-under-test" | awk '{print $1}')
[ "$BEFORE_SUM" = "$AFTER_SUM" ] && ok "binary untouched after hash mismatch" || bad "tampered artefact was installed"
grep -qiE "hash mismatch|upgrade manifest rejected" "$DATA/agent-tampered.log" && ok "hash mismatch reported" || { tail -5 "$DATA/agent-tampered.log"; bad "no hash mismatch in log"; }

say "valid release must be installed"
cp "$DATA/artefact.good" "$ART"
timeout 20 "$DATA/agent-under-test" run --state-dir "$DATA/agent" --enforcer observe \
  --auto-upgrade --upgrade-interval 1s > "$DATA/agent-upgrade.log" 2>&1
RC=$?
[ $RC -eq 0 ] && ok "agent exited 0 after staging the upgrade" || { tail -10 "$DATA/agent-upgrade.log"; bad "agent exit code $RC"; }
grep -q "agent binary upgraded" "$DATA/agent-upgrade.log" && ok "upgrade logged" || { tail -10 "$DATA/agent-upgrade.log"; bad "upgrade not logged"; }
if cmp -s "$DATA/agent-under-test" "$DATA/release.bin"; then ok "binary replaced with the signed release"; else bad "binary was not replaced"; fi
[ -x "$DATA/agent-under-test" ] && ok "replaced binary is executable" || bad "replaced binary lost its exec bit"
[ ! -e "$DATA/agent/upgrade/tg-agent-9.9.9.tmp" ] && ok "temporary download cleaned up" || bad "leftover temporary file"

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (upgrade) PASS"; else
  echo "E2E (upgrade) FAILED"
  echo "--- server ---"; tail -20 "$DATA/server.log"
fi
exit "$FAIL"
