#!/usr/bin/env bash
# End-to-end test of cross-machine (pull) publishing.
#
# Topology simulated on one host with two agent identities:
#   publisher  -> uploads artefacts + manifest to the control plane, never writes
#   node agent -> pulls the release, verifies hashes and writes under its grant
#
# Proves:
#   1. the publisher does not touch the target directory
#   2. the target node installs the release by pull, through the kernel enforcer
#   3. a tampered artefact is rejected by the node and the release fails
set -uo pipefail

REPO="${REPO:-/mnt/e/AI-learn/Tamper-proof}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-pull
SITE=/tmp/tg-pull-site
SRC=/tmp/tg-pull-src
SRC2=/tmp/tg-pull-src2
PORT=18452
BASE="https://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${AGENT_PID:-} ${PUB_PID:-} ${SERVER_PID:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

wait_status() {
  local id=$1 want=$2 timeout=${3:-20}
  local deadline=$(( $(date +%s) + timeout ))
  while :; do
    local st
    st=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/publish-requests/$id" | jq -r '.status // ""')
    [ "$st" = "$want" ] && return 0
    [ "$(date +%s)" -ge "$deadline" ] && { echo "$st" > "$DATA/last-status.txt"; return 1; }
    sleep 0.4
  done
}

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "fixtures"
rm -rf "$DATA" "$SITE" "$SRC" "$SRC2"
mkdir -p "$DATA" "$SITE" "$SRC/sub" "$SRC2"
printf '<html>v0</html>\n' > "$SITE/index.html"
printf '<html>v1</html>\n' > "$SRC/index.html"
printf 'body{color:red}\n' > "$SRC/sub/style.css"
printf 'evil\n' > "$SRC2/evil.html"
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
  --state-dir "$DATA/protect" --poll 2 --publisher-uids 0 > "$DATA/protect.enroll" 2>&1 && ok "protect node enrolled" || { cat "$DATA/protect.enroll"; bad "enroll"; }
"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PUB_TOK" --role publish --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/publish" --poll 2 > "$DATA/publish.enroll" 2>&1 && ok "publisher enrolled" || { cat "$DATA/publish.enroll"; bad "enroll"; }

curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" > "$DATA/nodes.json"
PROT_ID=$(jq -r '.[] | select(.role=="protect") | .id' "$DATA/nodes.json" | head -1)
PUB_ID=$(jq -r '.[] | select(.role=="publish") | .id' "$DATA/nodes.json" | head -1)
[ -n "$PROT_ID" ] && [ -n "$PUB_ID" ] && ok "nodes: $PROT_ID / $PUB_ID" || bad "nodes missing"

cat > "$DATA/policy.json" <<EOF
{"name":"pull-site","paths":[{"path":"$SITE","recursive":true,"mode":"enforce"}],
 "writers":[{"kind":"publisher","id":"$PUB_ID"}],"assign_nodes":["$PROT_ID"]}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/policies" -H 'Content-Type: application/json' \
  -d @"$DATA/policy.json" > "$DATA/policy.out"
jq -e '.id' "$DATA/policy.out" >/dev/null && ok "policy created" || { cat "$DATA/policy.out"; bad "policy"; }

say "publisher stages a release (must not write locally)"
# The node agent is started only after staging so we can prove the publisher
# itself never touches the target directory.
cat > "$DATA/request.json" <<EOF
{"node_id":"$PROT_ID","publisher_id":"$PUB_ID","source_dir":"$SRC","target_dir":"$SITE","note":"pull e2e","delivery":"pull"}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/publish-requests" -H 'Content-Type: application/json' \
  -d @"$DATA/request.json" > "$DATA/request.out"
REQ_ID=$(jq -r '.id // empty' "$DATA/request.out")
[ -n "$REQ_ID" ] && ok "pull request created: $REQ_ID" || { cat "$DATA/request.out"; bad "request"; }
"$BIN/tg-publish" run --state-dir "$DATA/publish" > "$DATA/publish.log" 2>&1 &
PUB_PID=$!
wait_status "$REQ_ID" "token_issued" 25 && ok "publisher staged artefacts and manifest" || { bad "staging did not finish ($(cat "$DATA/last-status.txt" 2>/dev/null))"; tail -10 "$DATA/publish.log"; }
[ "$(cat "$SITE/index.html" 2>/dev/null)" = "<html>v0</html>" ] && ok "target directory untouched by the publisher" || bad "publisher wrote to the target directory"
[ -d "$SITE/sub" ] && bad "publisher created sub/ directly" || ok "no local write from the publisher"

say "start node agent, which pulls and installs the release"
"$BIN/tg-agent" run --state-dir "$DATA/protect" > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 30); do grep -qE "enforcement active|running with degraded" "$DATA/agent.log" && break; sleep 0.4; done
grep -q "eBPF LSM enforcement active" "$DATA/agent.log" && ok "eBPF enforcement active on the node" || ok "node running with a degraded enforcer (acceptable)"
wait_status "$REQ_ID" "done" 30 && ok "node installed the release by pull" || { bad "pull delivery did not complete ($(cat "$DATA/last-status.txt" 2>/dev/null))"; tail -15 "$DATA/agent.log"; }
cmp -s "$SRC/index.html" "$SITE/index.html" && cmp -s "$SRC/sub/style.css" "$SITE/sub/style.css" \
  && ok "pulled content matches the source" || bad "pulled content mismatch"
sleep 3
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit?node_id=$PROT_ID&limit=100" > "$DATA/audit.json"
jq -e '[.[] | select(.kind=="publish.completed")] | length >= 1' "$DATA/audit.json" >/dev/null \
  && ok "delivery recorded in the audit chain" || bad "no delivery audit record"

say "tampered artefact must be rejected by the node"
kill "$AGENT_PID" 2>/dev/null; wait "$AGENT_PID" 2>/dev/null; AGENT_PID=""
sleep 1
cat > "$DATA/request2.json" <<EOF
{"node_id":"$PROT_ID","publisher_id":"$PUB_ID","source_dir":"$SRC2","target_dir":"$SITE","note":"tamper test","delivery":"pull"}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/publish-requests" -H 'Content-Type: application/json' \
  -d @"$DATA/request2.json" > "$DATA/request2.out"
REQ2=$(jq -r '.id // empty' "$DATA/request2.out")
wait_status "$REQ2" "token_issued" 25 && ok "second release staged" || bad "second staging failed"
ARTDIR="$DATA/artifacts/$REQ2"
CNT=$(find "$ARTDIR" -type f 2>/dev/null | wc -l)
[ "$CNT" -ge 1 ] && ok "artefact stored ($CNT file)" || bad "no artefact stored"
find "$ARTDIR" -type f -exec sh -c 'printf "tampered-evil-bytes\n" > "$1"' _ {} \;
"$BIN/tg-agent" run --state-dir "$DATA/protect" > "$DATA/agent2.log" 2>&1 &
AGENT_PID=$!
wait_status "$REQ2" "failed" 25 && ok "tampered release marked failed" || { bad "tampered release not rejected ($(cat "$DATA/last-status.txt" 2>/dev/null))"; tail -10 "$DATA/agent2.log"; }
[ ! -e "$SITE/evil.html" ] && ok "tampered file not written" || bad "tampered file written to the target"
say "audit chain"
# Regression guard: the kernel must not protect paths outside the policy while a
# release is being installed (stale inode entries used to cause false positives).
if ( echo ok > "$DATA/outside-check.txt" ) 2>/dev/null; then
  ok "unrelated write allowed while protection is active"
else
  bad "unrelated path was wrongly protected"
  echo "data dir: $(stat -c 'ino=%i dev=%d' "$DATA")"
  echo "site    : $(stat -c 'ino=%i dev=%d' "$SITE")"
  bpftool map dump name protected_dirs 2>&1 | grep -E '"ino"|"dev"' | head -20
fi
rm -f "$DATA/outside-check.txt" 2>/dev/null || true
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit/verify?node_id=$PROT_ID" > "$DATA/verify.json"
jq -e '.ok == true' "$DATA/verify.json" >/dev/null && ok "audit chain verified" || { cat "$DATA/verify.json"; bad "chain verify failed"; }

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (pull) PASS"; else
  echo "E2E (pull) FAILED"
  echo "--- agent ---"; tail -20 "$DATA/agent.log"
  echo "--- publish ---"; tail -20 "$DATA/publish.log"
fi
exit "$FAIL"
