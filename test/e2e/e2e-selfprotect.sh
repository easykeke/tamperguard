#!/usr/bin/env bash
# Proves kernel-level self-protection of the agent's own files (P6.2+).
#
# The agent protects its binary, unit and agent.json; only the agent's own pid is
# allowed to write them. A root shell must get EPERM.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-selfprotect
AGENT_BIN="$DATA/bin/tg-agent"
PORT=18469
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
  rm -rf "$DATA"
}
trap cleanup EXIT

say "preconditions"
[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }
grep -q 'lsm=.*bpf' /proc/cmdline || { echo "no bpf LSM in kernel cmdline"; exit 1; }
ok "root + bpf LSM present"

say "build and stage a private agent copy"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
rm -rf "$DATA"; mkdir -p "$DATA/bin"
cp "$BIN/tg-agent" "$AGENT_BIN"
ok "agent copy staged"

say "control plane"
"$BIN/tg-server" init --data-dir "$DATA/server" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA/server" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }
"$AGENT_BIN" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/server/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 --publisher-uids 0 > "$DATA/enroll.log" 2>&1 \
  && ok "protect enrolled" || { cat "$DATA/enroll.log"; bad "enroll"; }

say "start agent (self-protection)"
"$AGENT_BIN" run --state-dir "$DATA/protect" > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 30); do grep -q "self-protection active" "$DATA/agent.log" && break; sleep 0.4; done
if grep -q "self-protection active" "$DATA/agent.log"; then
  ok "self-protection active: $(grep -o 'paths=[0-9]*' "$DATA/agent.log" | head -1)"
else
  tail -10 "$DATA/agent.log"; bad "self-protection not active"; exit 1
fi
sleep 2

say "root changes the protected config (must be EPERM)"
# The executable is intentionally not in the kernel-protected set (exec would
# break), so the config file is the meaningful self-protection target here.
( chmod 600 "$DATA/protect/agent.json" ) 2>"$DATA/w1.err"
[ $? -ne 0 ] && ok "config chmod denied: $(head -1 "$DATA/w1.err")" || bad "config chmod SUCCEEDED"

say "root writes to agent.json (must be EPERM)"
( echo x >> "$DATA/protect/agent.json" ) 2>"$DATA/w2.err"
[ $? -ne 0 ] && ok "config write denied" || bad "config write SUCCEEDED"

say "agent keeps working"
sleep 2
curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")\"}" >/dev/null
STATUS=$(curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" | jq -r '.[0].status // ""')
[ "$STATUS" = "online" ] && ok "node still online (agent can write its own files)" || bad "node status=$STATUS"

say "explicit detach releases the protection"
"$BIN/tg-agent" ebpf-detach > "$DATA/detach.log" 2>&1 && ok "$(cat "$DATA/detach.log")" || bad "detach failed"
( chmod 600 "$DATA/protect/agent.json" ) 2>"$DATA/w3.err"
[ $? -eq 0 ] && ok "root can chmod the config after explicit detach" || { cat "$DATA/w3.err"; bad "still blocked after detach"; }

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (selfprotect) PASS"; else
  echo "E2E (selfprotect) FAILED"
  tail -20 "$DATA/agent.log" 2>/dev/null
fi
exit "$FAIL"
