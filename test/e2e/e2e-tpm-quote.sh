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
go build -o "$BIN"/ ./cmd/... || { echo "build failed"; exit 1; }
ok "binaries built"

say "software TPM and attestation key"
rm -rf "$DATA"; mkdir -p "$DATA/tpm" "$DATA/keys"
swtpm socket --tpm2 --tpmstate dir="$DATA/tpm" \
  --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear > "$DATA/swtpm.log" 2>&1 &
SWTPM_PID=$!
for _ in $(seq 1 30); do (exec 3<>/dev/tcp/127.0.0.1/2321) 2>/dev/null && break; sleep 0.2; done
export TPM2TOOLS_TCTI="$TCTI"
cd "$DATA/keys" || exit 1
tpm2_createek -G ecc -c ek.ctx > "$DATA/prov.log" 2>&1 || { cat "$DATA/prov.log"; bad "create EK"; exit 1; }
tpm2_createak -C ek.ctx -G ecc -g sha256 -s ecdsa -c ak.ctx -u ak.pem -f pem >> "$DATA/prov.log" 2>&1 || { cat "$DATA/prov.log"; bad "create AK"; exit 1; }
# The TPM only has a few transient slots; release the provisioning handles.
tpm2_flushcontext -t >> "$DATA/prov.log" 2>&1 || true
[ -s ak.pem ] && ok "AK provisioned" || bad "AK public key missing"

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
  --state-dir "$DATA/protect" --poll 2 --tpm-ak-pub "$DATA/keys/ak.pem" > "$DATA/enroll.log" 2>&1 \
  && ok "protect enrolled with AK" || { cat "$DATA/enroll.log"; bad "enroll"; exit 1; }

say "agent answers the nonce with a TPM quote"
"$BIN/tg-agent" run --state-dir "$DATA/protect" \
  --tpm-ak-ctx "$DATA/keys/ak.ctx" --tpm-tcti "$TCTI" > "$DATA/agent.log" 2>&1 &
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
