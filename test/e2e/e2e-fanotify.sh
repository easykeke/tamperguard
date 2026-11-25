#!/usr/bin/env bash
# End-to-end test of the DEGRADED (fanotify) path.
#
# Requires: Linux, root, CONFIG_FANOTIFY. No bpf LSM needed.
# Run inside WSL2/Ubuntu:  sudo bash test/e2e/e2e-fanotify.sh
#
# What it proves (degraded mode is detect-and-restore, not blocking):
#   1. an unauthorised overwrite of a protected file is reverted
#   2. an unauthorised created file is removed by the periodic scan
#   3. the release agent can write while its token is live (content kept)
#   4. after revocation writes are reverted again
#   5. blocked events reach the audit chain
set -uo pipefail

REPO="${REPO:-/mnt/e/AI-learn/Tamper-proof}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-fan
SITE=/tmp/tg-site-fan
SRC=/tmp/tg-src-fan
PORT=18446
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
}
trap cleanup EXIT

wait_content() {
  local path=$1 want=$2 timeout=${3:-6}
  local deadline=$(( $(date +%s) + timeout ))
  while [ "$(cat "$path" 2>/dev/null)" != "$want" ]; do
    [ "$(date +%s)" -ge "$deadline" ] && return 1
    sleep 0.1
  done
  return 0
}

say "preconditions"
[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }
[ -e /proc/sys/fs/fanotify/max_user_watches ] || echo "  (no fanotify sysctl, continuing)"
ok "running as root"

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
chmod 666 "$SITE/index.html"
ok "fixtures created (world-writable so only the enforcer can stop a write)"

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

say "start protect agent (fanotify, degraded)"
TG_FAN_SCAN_SECONDS=2 "$BIN/tg-agent" run --state-dir "$DATA/protect" --enforcer fanotify > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 30); do grep -q "fanotify: baseline snapshot" "$DATA/agent.log" && break; sleep 0.3; done
if grep -q "fanotify: baseline snapshot" "$DATA/agent.log"; then
  ok "fanotify active: $(grep -o 'paths=[0-9]*' "$DATA/agent.log" | head -1) baseline paths"
else
  bad "fanotify did not start"; tail -10 "$DATA/agent.log"; exit 1
fi

say "webshell overwrite as uid $NOBODY (must be reverted)"
setpriv --reuid=$NOBODY --regid=$NOBODY --clear-groups bash -c "echo 'evil' > $SITE/index.html" 2>/dev/null
wait_content "$SITE/index.html" "<html>v0</html>" && ok "overwrite reverted to the baseline" || bad "overwrite NOT reverted (content=$(cat "$SITE/index.html" 2>/dev/null))"

say "webshell creation as uid $NOBODY (must be removed)"
setpriv --reuid=$NOBODY --regid=$NOBODY --clear-groups bash -c "echo '<?php evil(); ?>' > $SITE/shell.php" 2>/dev/null
deadline=$(( $(date +%s) + 8 ))
while [ -e "$SITE/shell.php" ] && [ "$(date +%s)" -lt "$deadline" ]; do sleep 0.2; done
[ ! -e "$SITE/shell.php" ] && ok "created shell removed by the scan" || bad "created shell still present"

say "publish release (root publisher with live token)"
cat > "$DATA/request.json" <<EOF
{"node_id":"$PROT_ID","publisher_id":"$PUB_ID","source_dir":"$SRC","target_dir":"$SITE","note":"e2e fanotify"}
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
[ "$STATUS" = "done" ] && ok "release completed" || { bad "release status=$STATUS"; tail -12 "$DATA/publish.log"; }
if cmp -s "$SRC/index.html" "$SITE/index.html"; then ok "published content kept"; else bad "published content was reverted (degraded mode refused the release)"; fi

say "revoke publisher, then overwrite as root (must be reverted)"
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/revocations" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"subject\",\"value\":\"$PUB_ID\",\"reason\":\"e2e\"}" >/dev/null
sleep 3
echo "tampered" > "$SITE/index.html"
wait_content "$SITE/index.html" "$(cat "$SRC/index.html")" && ok "write reverted after revocation" || bad "write kept after revocation"

say "audit chain"
sleep 3
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit?node_id=$PROT_ID&limit=100" > "$DATA/audit.json"
ACOUNT=$(jq 'length' "$DATA/audit.json")
BLOCKED=$(jq '[.[] | select(.kind=="write.blocked")] | length' "$DATA/audit.json")
[ "$ACOUNT" -gt 0 ] && ok "audit records: $ACOUNT (blocked/restored: $BLOCKED)" || bad "no audit records"
[ "$BLOCKED" -ge 1 ] && ok "restore events recorded" || bad "expected blocked events"
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit/verify?node_id=$PROT_ID" > "$DATA/verify.json"
jq -e '.ok == true' "$DATA/verify.json" >/dev/null && ok "audit chain verified" || { cat "$DATA/verify.json"; bad "chain verify"; }

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (fanotify) PASS"; else
  echo "E2E (fanotify) FAILED"
  echo "--- agent ---"; tail -20 "$DATA/agent.log"
  echo "--- publish ---"; tail -20 "$DATA/publish.log"
fi
exit "$FAIL"
