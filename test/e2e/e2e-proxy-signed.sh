#!/usr/bin/env bash
# End-to-end test of the signed-manifest mode of the web-layer proxy.
#
# Proves:
#   1. tg-proxy fetches the control-plane-signed site manifest for this node over
#      mTLS and stores the artifacts (verifying every hash)
#   2. the signed manifest is persisted with its signature
#   3. after tampering with the file on disk, visitors still receive the trusted
#      content and the response is marked restored
#   4. a manifest that is not control-plane signed is refused with --require-signed
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-proxy-signed
SITE=/tmp/tg-proxy-signed-site
SRC=/tmp/tg-proxy-signed-src
PSTATE="$DATA/proxy-state"
PORT=18463
BASE="https://127.0.0.1:$PORT"
PROXY_PORT=18464
PROXY="http://127.0.0.1:$PROXY_PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${AGENT_PID:-} ${PUB_PID:-} ${PROXY_PID:-} ${SERVER_PID:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$DATA" "$SITE" "$SRC"
}
trap cleanup EXIT

wait_status() {
  local id=$1 want=$2 timeout=${3:-40}
  local deadline=$(( $(date +%s) + timeout ))
  while :; do
    local st
    st=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/publish-requests/$id" | jq -r '.status // ""')
    [ "$st" = "$want" ] && return 0
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep 0.4
  done
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

say "fixtures"
rm -rf "$DATA" "$SITE" "$SRC"; mkdir -p "$DATA" "$SITE" "$SRC/static"
printf '<html>signed-v1</html>\n' > "$SRC/index.html"
printf 'console.log(1)\n' > "$SRC/static/app.js"
printf '<html>old</html>\n' > "$SITE/index.html"
ok "fixtures created"

say "control plane"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
PUB_TOK=$(sed -n 's/^  Bootstrap token (publish) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 --publisher-uids 0 > "$DATA/protect.enroll" 2>&1 && ok "protect enrolled" || { cat "$DATA/protect.enroll"; bad "enroll"; }
"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PUB_TOK" --role publish --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/publish" --poll 2 > "$DATA/publish.enroll" 2>&1 && ok "publisher enrolled" || { cat "$DATA/publish.enroll"; bad "enroll"; }

curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" > "$DATA/nodes.json"
PROT_ID=$(jq -r '.[] | select(.role=="protect") | .id' "$DATA/nodes.json" | head -1)
PUB_ID=$(jq -r '.[] | select(.role=="publish") | .id' "$DATA/nodes.json" | head -1)
[ -n "$PROT_ID" ] && [ -n "$PUB_ID" ] && ok "nodes: $PROT_ID / $PUB_ID" || bad "nodes missing"

cat > "$DATA/policy.json" <<EOF
{"name":"signed-site","paths":[{"path":"$SITE","recursive":true,"mode":"enforce"}],
 "writers":[{"kind":"publisher","id":"$PUB_ID"}],"assign_nodes":["$PROT_ID"]}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/policies" -H 'Content-Type: application/json' \
  -d @"$DATA/policy.json" > "$DATA/policy.out"
jq -e '.id' "$DATA/policy.out" >/dev/null && ok "policy created" || { cat "$DATA/policy.out"; bad "policy"; }

say "pull-mode release"
"$BIN/tg-agent" run --state-dir "$DATA/protect" --enforcer observe --auto-upgrade=false > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
sleep 2
cat > "$DATA/request.json" <<EOF
{"node_id":"$PROT_ID","publisher_id":"$PUB_ID","source_dir":"$SRC","target_dir":"$SITE","note":"signed manifest","delivery":"pull"}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/publish-requests" -H 'Content-Type: application/json' \
  -d @"$DATA/request.json" > "$DATA/request.out"
REQ_ID=$(jq -r '.id // empty' "$DATA/request.out")
[ -n "$REQ_ID" ] && ok "request created: $REQ_ID" || { cat "$DATA/request.out"; bad "request"; }
"$BIN/tg-publish" run --state-dir "$DATA/publish" > "$DATA/publish.log" 2>&1 &
PUB_PID=$!
wait_status "$REQ_ID" "done" 40 && ok "node installed the pull release" || { bad "pull delivery failed"; tail -20 "$DATA/agent.log"; }

say "tg-proxy sync (signed manifest)"
"$BIN/tg-proxy" --root "$SITE" --state "$PSTATE" --sync --agent-state "$DATA/protect" --snapshot-only > "$DATA/sync.log" 2>&1
SYNC_RC=$?
[ $SYNC_RC -eq 0 ] && ok "sync completed" || { cat "$DATA/sync.log"; bad "sync failed"; }
MANIFEST="$PSTATE/manifest.json"
jq -e '.signature and .release_id and (.entries | length) >= 2' "$MANIFEST" >/dev/null \
  && ok "signed manifest persisted ($(jq -r '.release_id' "$MANIFEST"))" || { cat "$MANIFEST"; bad "manifest not signed"; }
[ -f "$PSTATE/blobs/$(jq -r '.entries["index.html"].sha256' "$MANIFEST")" ] && ok "trusted blob stored" || bad "blob missing"

say "serve from the signed manifest, tamper is detected"
printf '<html>EVIL-SIGNED</html>\n' > "$SITE/index.html"
"$BIN/tg-proxy" --root "$SITE" --state "$PSTATE" --listen "127.0.0.1:$PROXY_PORT" \
  --no-snapshot --require-signed --agent-state "$DATA/protect" --audit "$DATA/proxy-audit.jsonl" > "$DATA/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 40); do curl -s --max-time 1 "$PROXY/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
BODY=$(curl -s -D "$DATA/h1" "$PROXY/")
[ "$BODY" = "<html>signed-v1</html>" ] && ok "trusted content served despite tampering" || { echo "$BODY"; bad "wrong content"; }
grep -qi 'X-TG-Integrity: restored' "$DATA/h1" && ok "response marked restored" || bad "missing restored header"
grep -q 'web.tamper-detected' "$DATA/proxy-audit.jsonl" && ok "tamper event audited" || { cat "$DATA/proxy-audit.jsonl" 2>/dev/null; bad "audit missing"; }
[ "$(curl -s "$PROXY/static/app.js")" = "console.log(1)" ] && ok "asset served" || bad "asset mismatch"

say "--require-signed refuses a local snapshot"
rm -rf "$DATA/unsigned-state"
"$BIN/tg-proxy" --root "$SITE" --state "$DATA/unsigned-state" --snapshot-only >/dev/null 2>&1
"$BIN/tg-proxy" --root "$SITE" --state "$DATA/unsigned-state" --listen "127.0.0.1:18465" \
  --no-snapshot --require-signed > "$DATA/unsigned.log" 2>&1
[ $? -ne 0 ] && ok "unsigned manifest refused" || bad "unsigned manifest accepted"

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (proxy-signed) PASS"; else
  echo "E2E (proxy-signed) FAILED"
  echo "--- sync ---"; tail -20 "$DATA/sync.log" 2>/dev/null
  echo "--- proxy ---"; tail -20 "$DATA/proxy.log" 2>/dev/null
fi
exit "$FAIL"
