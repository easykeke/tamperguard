#!/usr/bin/env bash
# End-to-end TPM 2.0 quote attestation using a software TPM (swtpm).
#
# Proves the full protocol without hardware: provision an AK, enrol it at the
# control plane, let the agent answer the heartbeat nonce with a real TPM quote,
# and verify the server accepts and stores it.
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
DATA=/tmp/tg-e2e-tpm
PORT=18471
BASE="https://127.0.0.1:$PORT"
TCTI="swtpm:host=127.0.0.1,port=2321"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${AGENT_PID:-} ${SERVER_PID:-} ${SWTPM_PID:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$DATA"
}
trap cleanup EXIT

say "preconditions"
[ "$(id -u)" = "0" ] || { echo "must run as root"; exit 1; }
command -v swtpm >/dev/null && command -v tpm2_quote >/dev/null || { echo "need swtpm and tpm2-tools"; exit 1; }
ok "swtpm and tpm2-tools present"

say "build"
cd "$REPO" || exit 1
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  [ -x "$BIN/tg-server" ] && [ -x "$BIN/tg-agent" ] || { echo "prebuilt binaries missing in $BIN"; exit 1; }
  ok "using prebuilt binaries"
else
  go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
  ok "binaries built"
fi

say "software TPM and attestation key"
rm -rf "$DATA"; mkdir -p "$DATA/tpm" "$DATA/keys"
swtpm socket --tpm2 --tpmstate dir="$DATA/tpm" \
  --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear > "$DATA/swtpm.log" 2>&1 &
SWTPM_PID=$!
for _ in $(seq 1 30); do (exec 3<>/dev/tcp/127.0.0.1/2321) 2>/dev/null && break; sleep 0.2; done
export TPM2TOOLS_TCTI="$TCTI"
ok "software TPM started (AK will be provisioned by the agent)"

say "control plane"
cd "$REPO" || exit 1
"$BIN/tg-server" init --data-dir "$DATA/server" --listen "127.0.0.1:$PORT" > "$DATA/init.out" 2>&1 || { cat "$DATA/init.out"; exit 1; }
PROT_TOK=$(sed -n 's/^  Bootstrap token (protect) *: //p' "$DATA/init.out")
ADMIN_PW=$(sed -n 's/^  Admin password  *: //p' "$DATA/init.out")
"$BIN/tg-server" serve --data-dir "$DATA/server" > "$DATA/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 40); do curl -sk --max-time 1 "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done
curl -sk "$BASE/healthz" >/dev/null && ok "server healthy" || { bad "server failed"; exit 1; }

say "enrol with the AK public key"
"$BIN/tg-agent" enroll --server "$BASE" --bootstrap "$PROT_TOK" --ca "$DATA/server/keys/ca.crt" \
  --state-dir "$DATA/protect" --poll 2 --tpm-auto-ak --tpm-tcti "$TCTI" > "$DATA/enroll.log" 2>&1 \
  && ok "protect enrolled with an auto-provisioned AK" || { cat "$DATA/enroll.log"; bad "enroll"; exit 1; }
grep -q 'TPM AK provisioned' "$DATA/enroll.log" && ok "agent created the AK itself" || bad "auto-provision message missing"
jq -e '.tpm_ak_ctx and .tpm_tcti' "$DATA/protect/agent.json" >/dev/null 2>&1 \
  && ok "AK context and TCTI persisted in agent state" || { cat "$DATA/protect/agent.json"; bad "state missing TPM fields"; }

say "agent answers the nonce with a TPM quote"
# No --tpm-* flags here: the agent must reuse what enrolment provisioned.
"$BIN/tg-agent" run --state-dir "$DATA/protect" > "$DATA/agent.log" 2>&1 &
AGENT_PID=$!
VERIFIED=""
for _ in $(seq 1 60); do
  VERIFIED=$(curl -sk -c "$DATA/cookies" -X POST "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" >/dev/null 2>&1; \
    curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" 2>/dev/null | jq -r '.[0].attestation.verified // empty' 2>/dev/null)
  [ "$VERIFIED" = "true" ] && break
  sleep 0.5
done
if [ "$VERIFIED" = "true" ]; then
  ok "TPM quote verified by the control plane"
else
  bad "quote was not verified"
  echo "--- agent ---"; tail -15 "$DATA/agent.log"
  echo "--- server ---"; grep -i 'tpm\|attest' "$DATA/server.log" | tail -5
fi
grep -q 'TPM quote verified' "$DATA/server.log" && ok "server recorded the verification" || bad "server log missing verification"
curl -sk -b "$DATA/cookies" "$BASE/api/v1/nodes" | jq -r '.[0].attestation' 2>/dev/null | head -5

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (tpm-quote) PASS"; else
  echo "E2E (tpm-quote) FAILED"
fi
exit "$FAIL"
