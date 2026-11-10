#!/bin/sh
# Collect everything needed to explain a failed ceremony into one file.
#
#   tools/browser-bridge/doctor.sh            # writes /tmp/swpk-doctor.txt and prints it
#   tools/browser-bridge/doctor.sh --quiet    # writes only
#
# Nothing here changes state: it reads the checkout, the processes, the socket,
# the bridge's health, and the last lines of both logs.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SOCK=${SWPASSKEY_HID_SOCKET:-/tmp/swpk.sock}
CTL=${SWPASSKEY_CTL_SOCKET:-/tmp/swpk-bridge.sock}
PORT=${SWPASSKEY_BRIDGE_PORT:-3000}
OUT=/tmp/swpk-doctor.txt
QUIET=${1:-}

{
  echo "== when =================================================="
  date -u "+%Y-%m-%dT%H:%M:%SZ"
  echo
  echo "== checkout ============================================="
  echo "root:   $ROOT"
  echo "branch: $(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  echo "code:   $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo '?')"
  echo "dirty:  $(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ') files"
  echo
  echo "== processes ============================================"
  pgrep -fl "swpasskeyd" || echo "(no swpasskeyd)"
  pgrep -fl "bridge_server.py" || echo "(no bridge)"
  echo "port $PORT holder: $(lsof -tiTCP:$PORT -sTCP:LISTEN 2>/dev/null | tr '\n' ' ' || true)"
  echo
  echo "== daemon socket ========================================"
  if [ -S "$SOCK" ]; then echo "$SOCK exists"; else echo "$SOCK MISSING"; fi
  echo "health: $(curl -s --max-time 2 "http://localhost:$PORT/health" || echo '(no answer)')"
  echo
  echo "== identity ============================================="
  if [ -x "$ROOT/build/debug/swpasskeyctl" ] && [ -S "$CTL" ]; then
    "$ROOT/build/debug/swpasskeyctl" --socket "$CTL" profiles 2>/dev/null |
      sed -n 's/.*"current":"\([^"]*\)".*/current profile: \1/p' || echo "current profile: ?"
    "$ROOT/build/debug/swpasskeyctl" --socket "$CTL" attestation 2>/dev/null || true
    "$ROOT/build/debug/swpasskeyctl" --socket "$CTL" stats 2>/dev/null |
      sed -n 's/.*\("make_cred_ok":[0-9]*\).*/counters: \1/p' || true
  else
    echo "(no ctl socket at $CTL)"
  fi
  echo
  echo "== ceremonies (bridge log, last 40) ====================="
  tail -n 40 /tmp/bridge.log 2>/dev/null || echo "(no /tmp/bridge.log)"
  echo
  echo "== daemon log (last 20) ================================"
  tail -n 20 /tmp/bridge-daemon.log 2>/dev/null || echo "(no /tmp/bridge-daemon.log)"
  echo
  echo "== bridge log banner (code SHA) ========================"
  head -n 4 /tmp/bridge.log 2>/dev/null || true
} > "$OUT" 2>&1

if [ "$QUIET" != "--quiet" ]; then
  cat "$OUT"
else
  echo "wrote $OUT"
fi
