#!/usr/bin/env bash
# End-to-end test of the agent uninstall control.
#
# Proves that an agent cannot be removed locally by design:
#   1. a client request stays pending and is refused when the administrator denies
#   2. after approval the client receives a signed challenge code and can proceed
#      (dry-run here: nothing is actually deleted)
#   3. the management plane can generate the same ticket directly
#   4. a modified ticket is rejected
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-uninstall
PORT=18466
BASE="https://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$DATA"
}
trap cleanup EXIT

json() { curl -sk -b "$DATA/cookies" "$@"; }

wait_request_id() {
  local file=$1 want=${2:-20}
  for _ in $(seq 1 "$want"); do
    local id
    id=$(sed -n 's/^request_id=//p' "$file" 2>/dev/null | head -1)
    [ -n "$id" ] && { echo "$id"; return 0; }
    sleep 0.3
  done
  return 1
}

wait_pid() {
  local pid=$1 limit=${2:-30}
  for _ in $(seq 1 "$limit"); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.3
  done
  return 1
}

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
rm -rf "$DATA"; mkdir -p "$DATA"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 --publisher-uids 0 > "$DATA/enroll.log" 2>&1 && ok "protect enrolled" || { cat "$DATA/enroll.log"; bad "enroll"; }
curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
NODE_ID=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" | jq -r '.[0].id')
[ -n "$NODE_ID" ] || { bad "node id missing"; exit 1; }

say "deny path"
"$BIN/tg-agent" uninstall --state-dir "$DATA/protect" --reason "e2e deny" --timeout 30s --dry-run \
  > "$DATA/deny.log" 2>&1 &
CLI_PID=$!
REQ_ID=$(wait_request_id "$DATA/deny.log") || { cat "$DATA/deny.log"; bad "no request id"; }
[ -n "$REQ_ID" ] && ok "pending request created: $REQ_ID"
json "$BASE/api/v1/uninstall-requests?status=pending" | jq -e --arg id "$REQ_ID" '.[] | select(.id==$id)' >/dev/null \
  && ok "request visible to the administrator" || bad "pending request missing"
json -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/uninstall-requests/$REQ_ID/deny" >/dev/null
wait_pid "$CLI_PID" 30 || bad "client did not stop after denial"
grep -q 'denied' "$DATA/deny.log" && ok "client reports the denial" || { cat "$DATA/deny.log"; bad "denial not reported"; }
CLI_PID=""

say "approve path (challenge code)"
"$BIN/tg-agent" uninstall --state-dir "$DATA/protect" --reason "e2e approve" --timeout 30s --dry-run \
  > "$DATA/approve.log" 2>&1 &
CLI_PID=$!
REQ_ID=$(wait_request_id "$DATA/approve.log") || { cat "$DATA/approve.log"; bad "no request id"; }
RESP=$(json -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/uninstall-requests/$REQ_ID/approve")
TICKET=$(echo "$RESP" | jq -r '.ticket // empty')
[ "$(echo "$RESP" | jq -r '.status')" = "approved" ] && ok "administrator approved" || { echo "$RESP"; bad "approve failed"; }
[ -n "$TICKET" ] && ok "challenge code issued" || bad "no ticket"
wait_pid "$CLI_PID" 40 || bad "client did not finish"
grep -q 'challenge verified' "$DATA/approve.log" && ok "client verified the challenge" || { cat "$DATA/approve.log"; bad "challenge not verified"; }
grep -q 'dry-run: no files were removed' "$DATA/approve.log" && ok "dry-run completed" || bad "dry-run missing"
CLI_PID=""

say "management-plane path"
RESP=$(json -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/nodes/$NODE_ID/uninstall")
MTICKET=$(echo "$RESP" | jq -r '.ticket // empty')
[ -n "$MTICKET" ] && ok "management plane issued a ticket" || { echo "$RESP"; bad "no management ticket"; }
"$BIN/tg-agent" uninstall --state-dir "$DATA/protect" --ticket "$MTICKET" --dry-run > "$DATA/mgmt.log" 2>&1
[ $? -eq 0 ] && grep -q 'challenge verified' "$DATA/mgmt.log" && ok "ticket accepted" || { cat "$DATA/mgmt.log"; bad "ticket rejected"; }

say "tampered ticket is rejected"
BAD="${MTICKET%?}A"
"$BIN/tg-agent" uninstall --state-dir "$DATA/protect" --ticket "$BAD" --dry-run > "$DATA/bad.log" 2>&1
[ $? -ne 0 ] && grep -qi 'rejected' "$DATA/bad.log" && ok "tampered ticket rejected" || { cat "$DATA/bad.log"; bad "tampered ticket accepted"; }

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (uninstall) PASS"; else
  echo "E2E (uninstall) FAILED"
  echo "--- approve ---"; tail -10 "$DATA/approve.log" 2>/dev/null
  echo "--- server ---"; tail -10 "$DATA/server.log" 2>/dev/null
fi
exit "$FAIL"
