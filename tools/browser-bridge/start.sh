#!/bin/sh
# Start the daemon (socket transport) and the browser bridge together, and prove
# both are alive before printing the next step.
#
#   tools/browser-bridge/start.sh [profile] [pin]
#
# Defaults: yubikey-5c-nfc-5.8, PIN 123456, socket /tmp/swpk.sock, store
# /tmp/swpk-bridge.bin. Environment wins over the defaults:
#   SWPASSKEY_HID_SOCKET, SWPASSKEY_STORE, SWPASSKEY_CTL_SOCKET,
#   SWPASSKEY_BRIDGE_PIN, SWPASSKEY_BRIDGE_PORT, SWPASSKEY_PROFILE
#
# A missing daemon socket is the failure that costs the most time, so this script
# refuses to start the bridge until the socket exists, and prints the daemon log
# when it never appears.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PROFILE=${1:-${SWPASSKEY_PROFILE:-yubikey-5c-nfc-5.8}}
PIN=${2:-${SWPASSKEY_BRIDGE_PIN:-123456}}
SOCK=${SWPASSKEY_HID_SOCKET:-/tmp/swpk.sock}
STORE=${SWPASSKEY_STORE:-/tmp/swpk-bridge.bin}
CTL=${SWPASSKEY_CTL_SOCKET:-/tmp/swpk-bridge.sock}
PORT=${SWPASSKEY_BRIDGE_PORT:-3000}
DAEMON="$ROOT/build/debug/swpasskeyd"
CTL_BIN="$ROOT/build/debug/swpasskeyctl"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY=python3

[ -x "$DAEMON" ] || {
  echo "start.sh: $DAEMON missing; build it first:" >&2
  echo "  cd $ROOT && cmake --preset debug && cmake --build build/debug -j" >&2
  exit 1
}

# --testing auto-approves presence and only exists in Debug builds; say so rather
# than letting the daemon exit with 'presence_testing_refused'.
if ! strings "$DAEMON" | grep -q "SWPASSKEY_TESTING"; then
  echo "start.sh: warning: this build may refuse --testing (release build?)" >&2
fi

echo "start.sh: stopping previous instances"
pkill -f "swpasskeyd --testing" 2>/dev/null || true
pkill -f "browser-bridge/bridge_server.py" 2>/dev/null || true
sleep 0.5
rm -f "$SOCK" "$CTL"

echo "start.sh: daemon -> $SOCK (store $STORE)"
SWPASSKEY_HID_SOCKET="$SOCK" SWPASSKEY_LOG=warn \
  "$DAEMON" --testing --key-backend=software --store "$STORE" --ctl-socket "$CTL" \
  > /tmp/bridge-daemon.log 2>&1 &

i=0
while [ ! -S "$SOCK" ]; do
  i=$((i + 1))
  if [ "$i" -gt 50 ]; then
    echo "start.sh: daemon never created $SOCK. Its log:" >&2
    tail -n 15 /tmp/bridge-daemon.log >&2
    exit 1
  fi
  sleep 0.1
done

if [ -x "$CTL_BIN" ]; then
  "$CTL_BIN" --socket "$CTL" set-profile "$PROFILE" >/dev/null || {
    echo "start.sh: could not set profile $PROFILE" >&2
    exit 1
  }
  ATTEST=$("$CTL_BIN" --socket "$CTL" attestation)
else
  ATTEST="(swpasskeyctl missing)"
fi

echo "start.sh: bridge -> http://localhost:$PORT"
SWPASSKEY_BRIDGE_PIN="$PIN" "$PY" "$ROOT/tools/browser-bridge/bridge_server.py" \
  --hid-socket "$SOCK" --port "$PORT" >> /tmp/bridge.log 2>&1 &

i=0
while :; do
  health=$(curl -s --max-time 2 "http://localhost:$PORT/health" || true)
  case "$health" in
    *'"ok": true'*|*'"ok":true'*) break ;;
  esac
  i=$((i + 1))
  if [ "$i" -gt 50 ]; then
    echo "start.sh: bridge did not come up on port $PORT. Its log:" >&2
    tail -n 15 /tmp/bridge.log >&2
    exit 1
  fi
  sleep 0.1
done

cat <<EOF

profile   $PROFILE
attest    $ATTEST
bridge    http://localhost:$PORT/health
pin       $PIN (uv requests)
logs      /tmp/bridge.log (append)  /tmp/bridge-daemon.log

Next:
  cat $ROOT/tools/browser-bridge/bridge.js | pbcopy
  # on the site: reload, paste in DevTools console, press its own security-key button
  tail -f /tmp/bridge.log
EOF
