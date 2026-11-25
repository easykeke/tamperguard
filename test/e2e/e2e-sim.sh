#!/usr/bin/env bash
# End-to-end smoke test of the userspace pipeline:
#   server init -> enroll protect+publish agents -> policy -> publish -> audit
# Intended to run inside WSL/Linux as root.
set -uo pipefail

REPO=/mnt/e/AI-learn/Tamper-proof
BIN=$REPO/bin
DATA=/tmp/tg-e2e
SITE=/tmp/tg-site
SRC=/tmp/tg-src
PORT=18443
BASE=https://127.0.0.1:$PORT
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "${AGENT_PID:-}" ] && kill "$AGENT_PID" 2>/dev/null
  [ -n "${PUB_PID:-}" ] && kill "$PUB_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "fixtures"
rm -rf "$DATA" "$SITE" "$SRC"
mkdir -p "$DATA" "$SITE" "$SRC/sub"
printf '<html>v1</html>\n' > "$SRC/index.html"
printf 'body{}\n' > "$SRC/sub/style.css"
printf '<html>v0</html>\n' > "$SITE/index.html"
ok "fixtures created"

say "tg-server init"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
PUB_TOK=$(sed -n 's/^  Bootstrap token (publish) *: //p' "$DATA/init.out")
[ -n "$ADMIN_PW" ] && [ -n "$PROT_TOK" ] && [ -n "$PUB_TOK" ] && ok "init produced credentials" || { cat "$DATA/init.out"; bad "init output unparsable"; exit 1; }

say "start server"
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do
  curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break
  sleep 0.3
done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server did not start"; tail -20 "$DATA/server.log"; exit 1; }

say "enroll agents"
"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 > "$DATA/protect.enroll" 2>&1 && ok "protect agent enrolled" || { cat "$DATA/protect.enroll"; bad "protect enroll"; }
"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PUB_TOK" --role publish --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/publish" --poll 2 > "$DATA/publish.enroll" 2>&1 && ok "publish agent enrolled" || { cat "$DATA/publish.enroll"; bad "publish enroll"; }

say "login and read nodes"
curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" > "$DATA/login.json" || true
grep -q '"username"' "$DATA/login.json" && ok "login ok" || { cat "$DATA/login.json"; bad "login failed"; }

curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" > "$DATA/nodes.json"
PROT_ID=$(jq -r '.[] | select(.role=="protect") | .id' "$DATA/nodes.json" | head -1)
PUB_ID=$(jq -r '.[] | select(.role=="publish") | .id' "$DATA/nodes.json" | head -1)
[ -n "$PROT_ID" ] && [ -n "$PUB_ID" ] && ok "nodes registered: protect=$PROT_ID publish=$PUB_ID" || { cat "$DATA/nodes.json"; bad "nodes missing"; }

say "create policy"
cat > "$DATA/policy.json" <<EOF
{"name":"site-root","paths":[{"path":"$SITE","recursive":true,"mode":"enforce"}],
 "writers":[{"kind":"publisher","id":"$PUB_ID"}],"assign_nodes":["$PROT_ID"]}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/policies" \
  -H 'Content-Type: application/json' -d @"$DATA/policy.json" > "$DATA/policy.out"
POL_ID=$(jq -r '.id // empty' "$DATA/policy.out")
[ -n "$POL_ID" ] && ok "policy created: $POL_ID" || { cat "$DATA/policy.out"; bad "policy create failed"; }

say "start protect agent (sim enforcer)"
"$BIN/tg-agent" run --state-dir "$DATA/protect" --enforcer observe > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
sleep 3
grep -q "agent starting" "$DATA/agent.log" && ok "agent started" || { tail -20 "$DATA/agent.log"; bad "agent failed"; }
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes/$PROT_ID" > "$DATA/node.json"
DIGEST=$(jq -r '.node.policy_digest // ""' "$DATA/node.json")
[ -n "$DIGEST" ] && ok "agent synced policy digest ${DIGEST:0:12}..." || { cat "$DATA/node.json"; bad "agent did not sync policy"; }

say "publish release"
cat > "$DATA/request.json" <<EOF
{"node_id":"$PROT_ID","publisher_id":"$PUB_ID","source_dir":"$SRC","target_dir":"$SITE","note":"e2e"}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/publish-requests" \
  -H 'Content-Type: application/json' -d @"$DATA/request.json" > "$DATA/request.out" 2>/dev/null
grep -q 'missing source_dir or target_dir' "$DATA/request.out" && bad "target_dir not accepted by API"
REQ_ID=$(jq -r '.id // empty' "$DATA/request.out")
[ -n "$REQ_ID" ] && ok "request created: $REQ_ID" || { cat "$DATA/request.out"; bad "request create failed"; }

"$BIN/tg-publish" run --state-dir "$DATA/publish" > "$DATA/publish.log" 2>&1 &
PUB_PID=$!
for _ in $(seq 1 25); do
  status=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/publish-requests/$REQ_ID" | jq -r '.status // ""')
  [ "$status" = "done" ] && break
  sleep 1
done
status=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/publish-requests/$REQ_ID" | jq -r '.status // ""')
[ "$status" = "done" ] && ok "release completed" || { tail -30 "$DATA/publish.log"; bad "release status=$status"; }

if cmp -s "$SRC/index.html" "$SITE/index.html" && cmp -s "$SRC/sub/style.css" "$SITE/sub/style.css"; then
  ok "published files match source"
else
  bad "published content mismatch"
fi

say "audit chain"
sleep 2
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit?node_id=$PROT_ID&limit=20" > "$DATA/audit.json"
ACOUNT=$(jq 'length' "$DATA/audit.json")
[ "$ACOUNT" -gt 0 ] && ok "audit records received: $ACOUNT" || { bad "no audit records"; }
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit/verify?node_id=$PROT_ID" > "$DATA/verify.json"
jq -e '.ok == true' "$DATA/verify.json" >/dev/null && ok "audit chain verified" || { cat "$DATA/verify.json"; bad "chain verification failed"; }

say "revocation"
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/revocations" \
  -H 'Content-Type: application/json' -d '{"kind":"subject","value":"'"$PUB_ID"'","reason":"e2e"}' >/dev/null
sleep 3
REVS=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/revocations" | jq 'length')
[ "$REVS" -ge 1 ] && ok "revocation recorded" || bad "revocation missing"

say "result"
if [ "$FAIL" -eq 0 ]; then
  echo "E2E PASS"
else
  echo "E2E FAILED"
  echo "--- server ---"; tail -20 "$DATA/server.log"
  echo "--- agent ---"; tail -20 "$DATA/agent.log"
  echo "--- publish ---"; tail -20 "$DATA/publish.log"
fi
exit "$FAIL"
