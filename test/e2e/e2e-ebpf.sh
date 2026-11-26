#!/usr/bin/env bash
# Full end-to-end test with REAL kernel enforcement (eBPF LSM).
#
# Requires: Linux, root, a kernel with CONFIG_BPF_LSM and bpf in the LSM list.
# Run inside WSL2/Ubuntu:  sudo bash test/e2e/e2e-ebpf.sh
#
# What it proves:
#   1. a non-privileged process cannot write/create in the protected tree
#      (EPERM from the kernel, not from file permissions)
#   2. the release agent can write while its token is live
#   3. revoking the publisher closes the door again within one heartbeat
#   4. the audit chain still verifies
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-bpf
SITE=/tmp/tg-site-bpf
SRC=/tmp/tg-src-bpf
PORT=18444
BASE="https://127.0.0.1:$PORT"
FAIL=0
NOBODY=65534

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${AGENT_PID:-} ${PUB_PID:-} ${SERVER_PID:-}; do kill "$p" 2>/dev/null; done
  sleep 1
  wait 2>/dev/null
  # Pinned links intentionally survive the agent; clear them for the next test.
  "$BIN/tg-agent" ebpf-detach >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "preconditions"
[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }
if ! cat /proc/cmdline | grep -q 'lsm=.*bpf'; then
  echo "kernel command line has no bpf LSM; run: (see docs/quickstart.md)"; exit 1
fi
ok "running as root with bpf in the kernel LSM list"

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo build failed; exit 1; }
ok "binaries built"

say "fixtures"
rm -rf "$DATA" "$SITE" "$SRC"
mkdir -p "$DATA" "$SITE" "$SRC/sub"
printf '<html>v1</html>\n' > "$SRC/index.html"
printf 'body{}\n' > "$SRC/sub/style.css"
printf '<html>v0</html>\n' > "$SITE/index.html"
chmod 777 "$SITE"
ok "fixtures created (site dir is world-writable so only the kernel can stop a write)"

say "control plane"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
PUB_TOK=$(sed -n 's/^  Bootstrap token (publish) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; tail -5 "$DATA/server.log"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 --publisher-uids 0 > "$DATA/protect.enroll" 2>&1 || { cat "$DATA/protect.enroll"; bad "protect enroll"; }
"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PUB_TOK" --role publish --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/publish" --poll 2 > "$DATA/publish.enroll" 2>&1 || { cat "$DATA/publish.enroll"; bad "publish enroll"; }
ok "agents enrolled"

curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" > "$DATA/nodes.json"
PROT_ID=$(jq -r '.[] | select(.role=="protect") | .id' "$DATA/nodes.json" | head -1)
PUB_ID=$(jq -r '.[] | select(.role=="publish") | .id' "$DATA/nodes.json" | head -1)
[ -n "$PROT_ID" ] && [ -n "$PUB_ID" ] && ok "nodes: $PROT_ID / $PUB_ID" || bad "nodes missing"

cat > "$DATA/policy.json" <<EOF
{"name":"site","paths":[{"path":"$SITE","recursive":true,"mode":"enforce"}],
 "writers":[{"kind":"publisher","id":"$PUB_ID"}],"assign_nodes":["$PROT_ID"]}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/policies" -H 'Content-Type: application/json' \
  -d @"$DATA/policy.json" > "$DATA/policy.out"
jq -e '.id' "$DATA/policy.out" >/dev/null && ok "policy created" || { cat "$DATA/policy.out"; bad "policy"; }

say "start protect agent (eBPF LSM)"
"$BIN/tg-agent" run --state-dir "$DATA/protect" > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 25); do grep -q "eBPF LSM enforcement active" "$DATA/agent.log" && break; sleep 0.4; done
if grep -q "eBPF LSM enforcement active" "$DATA/agent.log"; then
  ok "eBPF LSM attached: $(grep -o 'hooks=[0-9]*' "$DATA/agent.log" | head -1)"
else
  bad "eBPF LSM did not attach"; tail -5 "$DATA/agent.log"; exit 1
fi
if grep -q "agent stream opened" "$DATA/server.log"; then
  ok "push stream (SSE) connected"
else
  bad "agent did not open the push stream"; tail -5 "$DATA/server.log"
fi
sleep 2

say "webshell write as uid $NOBODY (must be EPERM)"
setpriv --reuid=$NOBODY --regid=$NOBODY --clear-groups bash -c "echo '<?php evil(); ?>' > $SITE/shell.php" 2>"$DATA/ws.err"
WS_RC=$?
if [ $WS_RC -ne 0 ]; then ok "kernel denied the webshell write (rc=$WS_RC: $(head -1 "$DATA/ws.err"))"
else bad "webshell write SUCCEEDED"; fi

say "publish release (root publisher, live token)"
cat > "$DATA/request.json" <<EOF
{"node_id":"$PROT_ID","publisher_id":"$PUB_ID","source_dir":"$SRC","target_dir":"$SITE","note":"e2e"}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/publish-requests" -H 'Content-Type: application/json' \
  -d @"$DATA/request.json" > "$DATA/request.out"
REQ_ID=$(jq -r '.id // empty' "$DATA/request.out")
"$BIN/tg-publish" run --state-dir "$DATA/publish" > "$DATA/publish.log" 2>&1 &
PUB_PID=$!
STATUS=""
for _ in $(seq 1 40); do
  STATUS=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/publish-requests/$REQ_ID" | jq -r '.status // ""')
  [ "$STATUS" = "done" ] || [ "$STATUS" = "failed" ] && break
  sleep 1
done
if [ "$STATUS" = "done" ]; then ok "release completed"; else bad "release status=$STATUS"; tail -12 "$DATA/publish.log"; fi
if cmp -s "$SRC/index.html" "$SITE/index.html" && cmp -s "$SRC/sub/style.css" "$SITE/sub/style.css"; then
  ok "published content matches source"
else
  bad "published content mismatch"
fi

say "revoke publisher, then write as root (must be EPERM again)"
REVOKE_AT=$(date +%s)
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/revocations" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"subject\",\"value\":\"$PUB_ID\",\"reason\":\"e2e\"}" >/dev/null
# The revocation is pushed over SSE; 2s is a generous bound for the sync.
sleep 2
( echo evil > "$SITE/after-revoke.php" ) 2>"$DATA/rev.err"
RV_RC=$?
REVOKE_LATENCY=$(( $(date +%s) - REVOKE_AT ))
if [ $RV_RC -ne 0 ]; then ok "write denied ${REVOKE_LATENCY}s after revocation (rc=$RV_RC)"; else bad "write allowed after revocation"; fi

say "audit chain"
# Blocked events are uploaded on the agent's next tick; give it a moment.
sleep 3
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit?node_id=$PROT_ID&limit=100" > "$DATA/audit.json"
ACOUNT=$(jq 'length' "$DATA/audit.json")
BLOCKED=$(jq '[.[] | select(.kind=="write.blocked")] | length' "$DATA/audit.json")
[ "$ACOUNT" -gt 0 ] && ok "audit records: $ACOUNT (blocked: $BLOCKED)" || bad "no audit records"
[ "$BLOCKED" -ge 2 ] && ok "blocked events recorded for both attempts" || bad "expected >=2 blocked events"
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit/verify?node_id=$PROT_ID" > "$DATA/verify.json"
jq -e '.ok == true' "$DATA/verify.json" >/dev/null && ok "audit chain verified" || { cat "$DATA/verify.json"; bad "chain verify"; }

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (eBPF) PASS"; else
  echo "E2E (eBPF) FAILED"
  echo "--- agent ---"; tail -20 "$DATA/agent.log"
  echo "--- publish ---"; tail -20 "$DATA/publish.log"
fi
exit "$FAIL"
