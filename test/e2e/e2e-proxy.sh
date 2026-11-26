#!/usr/bin/env bash
# End-to-end test of the web-layer integrity proxy.
#
# Proves:
#   1. a snapshot is served with X-TG-Integrity: verified
#   2. after the file on disk is tampered with, visitors still get the trusted
#      content (X-TG-Integrity: restored) and the event is audited
#   3. files added to the document root after the snapshot are not served
#   4. unknown paths are forwarded to the upstream when one is configured
set -uo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
BIN="$REPO/bin"
BASE=/tmp/tg-e2e-proxy
SITE="$BASE/site"
STATE="$BASE/state"
AUDIT="$BASE/audit.jsonl"
PORT=18461
UP_PORT=18462
BASE_URL="http://127.0.0.1:$PORT"
FAIL=0

say() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }
bad() { printf '  [FAIL] %s\n' "$*"; FAIL=1; }

cleanup() {
  for p in ${PROXY_PID:-} ${UP_PID:-}; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$BASE"
}
trap cleanup EXIT

say "build"
cd "$REPO" || exit 1
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  [ -x "$BIN/tg-server" ] && [ -x "$BIN/tg-proxy" ] || { echo "prebuilt binaries missing"; exit 1; }
  ok "using prebuilt binaries"
else
  go build -o "$BIN"/ ./cmd/tg-proxy ./cmd/tg-server ./cmd/tg-agent || { echo "build failed"; exit 1; }
fi
ok "binaries built"

say "fixtures"
rm -rf "$BASE"; mkdir -p "$SITE/static"
printf '<html>trusted-v1</html>\n' > "$SITE/index.html"
printf 'console.log(1)\n' > "$SITE/static/app.js"
ok "site created"

say "snapshot"
"$BIN/tg-proxy" --root "$SITE" --state "$STATE" --snapshot-only > "$BASE/snapshot.log" 2>&1 \
  && ok "snapshot created" || { cat "$BASE/snapshot.log"; bad "snapshot failed"; }
[ -f "$STATE/manifest.json" ] && ok "manifest exists" || bad "manifest missing"

say "serve verified content"
"$BIN/tg-proxy" --root "$SITE" --state "$STATE" --listen "127.0.0.1:$PORT" \
  --audit "$AUDIT" > "$BASE/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 40); do curl -s --max-time 1 "$BASE_URL/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
BODY=$(curl -s -D "$BASE/h1" "$BASE_URL/")
[ "$BODY" = "<html>trusted-v1</html>" ] && ok "index served" || bad "index body: $BODY"
grep -qi 'X-TG-Integrity: verified' "$BASE/h1" && ok "header says verified" || bad "missing verified header"
[ "$(curl -s "$BASE_URL/static/app.js")" = "console.log(1)" ] && ok "asset served" || bad "asset mismatch"

say "tampered file is replaced by the trusted copy"
printf '<html>EVIL</html>\n' > "$SITE/index.html"
BODY=$(curl -s -D "$BASE/h2" "$BASE_URL/")
[ "$BODY" = "<html>trusted-v1</html>" ] && ok "visitor still sees trusted content" || bad "served tampered content: $BODY"
grep -qi 'X-TG-Integrity: restored' "$BASE/h2" && ok "header says restored" || bad "missing restored header"
grep -q 'web.tamper-detected' "$AUDIT" && ok "tamper event audited" || { cat "$AUDIT" 2>/dev/null; bad "no audit event"; }

say "files added after the snapshot are not served"
printf 'evil\n' > "$SITE/evil.html"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/evil.html")
[ "$CODE" = "404" ] && ok "unknown path is 404" || bad "unknown path status $CODE"

say "unknown paths reach the upstream"
kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null; PROXY_PID=""
cat > "$BASE/up.py" <<'PY'
import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("upstream:" + self.path).encode()
        self.send_response(200)
        self.send_header("X-Upstream", "yes")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
python3 "$BASE/up.py" "$UP_PORT" > "$BASE/upstream.log" 2>&1 &
UP_PID=$!
for _ in $(seq 1 40); do curl -s --max-time 1 "http://127.0.0.1:$UP_PORT/" >/dev/null 2>&1 && break; sleep 0.2; done
"$BIN/tg-proxy" --root "$SITE" --state "$STATE" --listen "127.0.0.1:$PORT" \
  --upstream "http://127.0.0.1:$UP_PORT" > "$BASE/proxy2.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 40); do curl -s --max-time 1 "$BASE_URL/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
BODY=$(curl -s -D "$BASE/h3" "$BASE_URL/dynamic/path")
[ "$BODY" = "upstream:/dynamic/path" ] && ok "dynamic request reached the upstream" || bad "upstream body: $BODY"
grep -qi 'X-Upstream: yes' "$BASE/h3" && ok "upstream response passed through" || bad "upstream header missing"

say "result"
if [ "$FAIL" -eq 0 ]; then echo "E2E (proxy) PASS"; else
  echo "E2E (proxy) FAILED"
  echo "--- proxy log ---"; tail -20 "$BASE/proxy.log"
fi
exit "$FAIL"
