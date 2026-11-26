#!/usr/bin/env bash
# Verifies P6.2 (agent self-check) and P6.3 (boot-evidence reporting).
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-selfcheck
PORT=18468
BASE="https://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${AGENT_PID:-} ${SERVER_PID:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$DATA"
}
trap cleanup EXIT

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "control plane"
rm -rf "$DATA"; mkdir -p "$DATA"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 > "$DATA/enroll.log" 2>&1 && ok "protect enrolled" || { cat "$DATA/enroll.log"; bad "enroll"; }

say "boot evidence in heartbeat"
"$BIN/tg-agent" run --state-dir "$DATA/protect" > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
sleep 4
curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" > "$DATA/nodes.json"
DIGEST=$(jq -r '.[0].caps.boot_digest // empty' "$DATA/nodes.json")
SB=$(jq -r '.[0].caps.secure_boot // empty' "$DATA/nodes.json")
[ -n "$DIGEST" ] && ok "boot digest reported: ${DIGEST:0:12}…" || { cat "$DATA/nodes.json"; bad "no boot digest"; }
[ -n "$SB" ] && ok "secure boot state reported: $SB" || bad "no secure boot state"

kill "$AGENT_PID" 2>/dev/null; wait "$AGENT_PID" 2>/dev/null; AGENT_PID=""

say "self-check baseline"
[ -f "$DATA/protect/selfcheck.json" ] && ok "baseline written" || bad "no baseline"
"$BIN/tg-agent" selfcheck --state-dir "$DATA/protect" > "$DATA/sc1.log" 2>&1
[ $? -eq 0 ] && grep -q 'selfcheck: OK' "$DATA/sc1.log" && ok "selfcheck OK before tampering" || { cat "$DATA/sc1.log"; bad "selfcheck failed early"; }

say "modified config is detected"
# Appending bytes changes the hash without making the file unparsable for this test.
printf 'x' >> "$DATA/protect/agent.json"
"$BIN/tg-agent" selfcheck --state-dir "$DATA/protect" > "$DATA/sc2.log" 2>&1
if [ $? -ne 0 ] && grep -q 'CHANGED' "$DATA/sc2.log"; then
  ok "selfcheck reports the changed file"
else
  cat "$DATA/sc2.log"; bad "selfcheck missed the change"
fi

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (selfcheck) PASS"; else
  echo "E2E (selfcheck) FAILED"
  tail -10 "$DATA/agent.log" 2>/dev/null
fi
exit "$FAIL"
