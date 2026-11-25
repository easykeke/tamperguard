#!/usr/bin/env bash
# End-to-end test of the Java RASP probe (SecurityManager based).
#
# Proves:
#   1. observe mode: the write happens and is recorded as rasp.observed
#   2. after the policy flips to enforce, the same write is blocked before it
#      lands and recorded as rasp.blocked
#   3. the probe picks up the rule change without restarting the JVM
set -uo pipefail

REPO="${REPO:-/mnt/e/AI-learn/Tamper-proof}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-java
SITE=/tmp/tg-rasp-java-site
PORT=18449
BASE="https://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${AGENT_PID:-} ${SERVER_PID:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

say "preconditions"
[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }
command -v javac >/dev/null || { echo "JDK is required (javac not found)"; exit 1; }
ok "$(java -version 2>&1 | head -1)"

say "build"
cd "$REPO" || exit 1
go build -o "$BIN"/ ./cmd/... || { echo build failed; exit 1; }
bash rasp/java/build.sh || { echo "java agent build failed"; exit 1; }
ok "binaries and tg-rasp.jar built"

say "control plane"
rm -rf "$DATA" "$SITE"
mkdir -p "$DATA" "$SITE"
printf '<html>v0</html>\n' > "$SITE/index.html"
"$BIN/tg-server" init --data-dir "$DATA" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }

"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/keys/ca.crt" \
  --state-dir "$DATA/agent" --poll 2 > "$DATA/enroll.log" 2>&1 && ok "agent enrolled" || { cat "$DATA/enroll.log"; bad "enroll"; }

curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" > "$DATA/nodes.json"
PROT_ID=$(jq -r '.[] | select(.role=="protect") | .id' "$DATA/nodes.json" | head -1)

cat > "$DATA/policy.json" <<EOF
{"name":"java-rasp","paths":[{"path":"$SITE","recursive":true,"mode":"observe"}],
 "writers":[],"assign_nodes":["$PROT_ID"]}
EOF
curl -sk -b "$DATA/cookies" -X POST "$BASE/api/v1/policies" -H 'Content-Type: application/json' \
  -d @"$DATA/policy.json" > "$DATA/policy.out"
POL_ID=$(jq -r '.id // empty' "$DATA/policy.out")
[ -n "$POL_ID" ] && ok "policy created in observe mode ($POL_ID)" || { cat "$DATA/policy.out"; bad "policy"; }

say "start agent with RASP socket"
"$BIN/tg-agent" run --state-dir "$DATA/agent" --enforcer observe --auto-upgrade=false --rasp \
  > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 30); do grep -q "rasp probe socket listening" "$DATA/agent.log" && break; sleep 0.3; done
RASP_SOCK=$(grep "rasp probe socket listening" "$DATA/agent.log" | sed -n 's/.*socket=\([^ ]*\).*/\1/p' | head -1)
[ -n "$RASP_SOCK" ] && ok "probe socket: $RASP_SOCK" || { cat "$DATA/agent.log"; bad "no rasp socket"; exit 1; }
sleep 3

say "build test application"
mkdir -p "$DATA/javaclasses"
cat > "$DATA/JavaApp.java" <<'EOF'
import java.io.FileOutputStream;

public class JavaApp {
    public static void main(String[] args) throws Exception {
        // Give the probe a moment to connect and receive the rules.
        Thread.sleep(EventWaitMillis());
        try (FileOutputStream out = new FileOutputStream(args[0])) {
            out.write("written-by-java-app\n".getBytes());
        }
        System.out.println("APP_WROTE_OK");
    }

    private static long EventWaitMillis() {
        String v = System.getenv("TG_APP_START_WAIT_MS");
        return v == null ? 800L : Long.parseLong(v);
    }
}
EOF
javac -d "$DATA/javaclasses" "$DATA/JavaApp.java" || { bad "javac failed"; exit 1; }
ok "test application compiled"

run_app() {
  java -Djava.security.manager=allow \
    "-javaagent:$REPO/dist/tg-rasp.jar=socket=$RASP_SOCK" \
    -cp "$DATA/javaclasses" JavaApp "$SITE/index.html" 2>&1
}

say "observe mode: write is allowed but recorded"
OUT=$(run_app); RC=$?
[ $RC -eq 0 ] && echo "$OUT" | grep -q APP_WROTE_OK && ok "application write succeeded in observe mode" || { echo "$OUT"; bad "observe write failed rc=$RC"; }
[ "$(cat "$SITE/index.html" 2>/dev/null | tr -d '\n')" = "written-by-java-app" ] && ok "file content changed" || bad "file content not written"
sleep 3
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit?node_id=$PROT_ID&limit=100" > "$DATA/audit1.json"
jq -e '[.[] | select(.kind=="rasp.observed")] | length >= 1' "$DATA/audit1.json" >/dev/null \
  && ok "rasp.observed recorded" || { jq 'map(.kind)' "$DATA/audit1.json"; bad "no rasp.observed audit"; }

say "switch the rule to enforce, no JVM restart"
cat > "$DATA/policy2.json" <<EOF
{"name":"java-rasp","paths":[{"path":"$SITE","recursive":true,"mode":"enforce"}],"writers":[]}
EOF
curl -sk -b "$DATA/cookies" -X PUT "$BASE/api/v1/policies/$POL_ID" -H 'Content-Type: application/json' \
  -d @"$DATA/policy2.json" > "$DATA/policy2.out"
jq -e '.version == 2' "$DATA/policy2.out" >/dev/null && ok "policy version bumped to 2" || { cat "$DATA/policy2.out"; bad "policy update"; }
sleep 3

OUT=$(run_app); RC=$?
[ $RC -ne 0 ] && ok "application write blocked (exit $RC)" || { echo "$OUT"; bad "write was not blocked in enforce mode"; }
echo "$OUT" | grep -q "blocked by the runtime policy" && ok "block message came from the probe" || { echo "$OUT"; bad "unexpected block message"; }
[ "$(cat "$SITE/index.html" 2>/dev/null | tr -d '\n')" = "written-by-java-app" ] && ok "file unchanged after blocked write" || bad "blocked write still landed"
sleep 3
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit?node_id=$PROT_ID&limit=100" > "$DATA/audit2.json"
jq -e '[.[] | select(.kind=="rasp.blocked")] | length >= 1' "$DATA/audit2.json" >/dev/null \
  && ok "rasp.blocked recorded" || { jq 'map(.kind)' "$DATA/audit2.json"; bad "no rasp.blocked audit"; }
curl -sk -b "$DATA/cookies" "$BASE/api/v1/audit/verify?node_id=$PROT_ID" > "$DATA/verify.json"
jq -e '.ok == true' "$DATA/verify.json" >/dev/null && ok "audit chain verified" || bad "chain verify failed"

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (rasp-java) PASS"; else
  echo "E2E (rasp-java) FAILED"
  echo "--- agent ---"; tail -20 "$DATA/agent.log"
fi
exit "$FAIL"
