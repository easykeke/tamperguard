#!/usr/bin/env bash
# Proves that eBPF LSM enforcement survives a killed agent.
#
# Requires: Linux, root, kernel with CONFIG_BPF_LSM and bpf in the LSM list.
#
# What it proves:
#   1. protected paths are blocked while the agent runs
#   2. after `kill -9` the pinned links keep blocking (no protection gap)
#   3. `tg-agent ebpf-detach` releases the pins for maintenance
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-pin
SITE=/tmp/tg-site-pin
PORT=18467
BASE="https://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  [ -n "${AGENT_PID:-}" ] && kill -9 "$AGENT_PID" 2>/dev/null
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null
  wait 2>/dev/null
  "$BIN/tg-agent" ebpf-detach >/dev/null 2>&1 || true
  rm -rf "$DATA" "$SITE"
}
trap cleanup EXIT

say "preconditions"
[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }
grep -q 'lsm=.*bpf' /proc/cmdline || { echo "no bpf LSM in kernel cmdline"; exit 1; }
ok "root + bpf LSM present"

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "fixtures"
rm -rf "$DATA" "$SITE"; mkdir -p "$DATA" "$SITE"
printf '<html>v0</html>\n' > "$SITE/index.html"
chmod 777 "$SITE"
ok "site ready"

say "control plane"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 --publisher-uids 0 > "$DATA/enroll.log" 2>&1 \
  && ok "protect enrolled" || { cat "$DATA/enroll.log"; bad "enroll"; }
curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
PROT_ID=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" | jq -r '.[0].id')
cat > "$DATA/policy.json" <<EOF
{"name":"pin","paths":[{"path":"$SITE","recursive":true,"mode":"enforce"}],
 "writers":[],"assign_nodes":["$PROT_ID"]}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/policies" -H 'Content-Type: application/json' \
  -d @"$DATA/policy.json" > "$DATA/policy.out"
jq -e '.id' "$DATA/policy.out" >/dev/null && ok "policy created" || { cat "$DATA/policy.out"; bad "policy"; }

say "start agent and verify enforcement"
"$BIN/tg-agent" run --state-dir "$DATA/protect" > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 30); do grep -q "eBPF LSM enforcement active" "$DATA/agent.log" && break; sleep 0.4; done
grep -q "eBPF LSM enforcement active" "$DATA/agent.log" && ok "eBPF attached" || { tail -8 "$DATA/agent.log"; bad "attach failed"; exit 1; }
sleep 2
( echo evil > "$SITE/blocked.php" ) 2>"$DATA/w1.err"
[ $? -ne 0 ] && ok "write blocked while running" || bad "write allowed while running"

say "kill -9 the agent"
if ls /sys/fs/bpf/tamperguard/* >/dev/null 2>&1; then
  ok "pinned links present: $(ls /sys/fs/bpf/tamperguard | wc -l)"
else
  bad "no pinned links under /sys/fs/bpf/tamperguard"
fi
kill -9 "$AGENT_PID" 2>/dev/null
wait "$AGENT_PID" 2>/dev/null
AGENT_PID=""
sleep 1
( echo evil > "$SITE/after-kill.php" ) 2>"$DATA/w2.err"
if [ $? -ne 0 ]; then
  ok "write STILL blocked after kill -9 (pinned link enforces)"
else
  bad "write allowed after kill -9: protection gap remains"
fi

say "maintenance detach"
"$BIN/tg-agent" ebpf-detach > "$DATA/detach.log" 2>&1
[ $? -eq 0 ] && ok "$(cat "$DATA/detach.log")" || { cat "$DATA/detach.log"; bad "detach failed"; }
( echo ok > "$SITE/after-detach.php" ) 2>"$DATA/w3.err"
if [ $? -eq 0 ]; then
  ok "write allowed after explicit detach"
else
  bad "still blocked after detach"
  echo "--- pins ---"; ls -la /sys/fs/bpf/tamperguard 2>&1 | head
  echo "--- links ---"; bpftool link show 2>&1 | head -20
  echo "--- lsm progs ---"; bpftool prog show 2>&1 | grep -i 'tg_' | head -5
fi

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (ebpf-pin) PASS"; else
  echo "E2E (ebpf-pin) FAILED"
  echo "--- agent ---"; tail -20 "$DATA/agent.log" 2>/dev/null
fi
exit "$FAIL"
