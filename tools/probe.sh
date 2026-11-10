#!/bin/sh
# Arm one of the remaining probes: restart the daemon with the right attestation
# material and the bridge that serves it, then print what to expect.
#
#   tools/probe.sh p1   # A-branch chain: leaf issuer = real anchor name + genuine A chain
#   tools/probe.sh p2   # self attestation (packed, no x5c) on an accepted AAGUID
#   tools/probe.sh p3   # reverse AAGUID split: authData says Titan, cert says Yubico
#   tools/probe.sh p4 <aaguid>   # claim another bundle model, default 4599062e (C Nano 5.7.4)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DAEMON="$ROOT/build/debug/swpasskeyd"
CTL="$ROOT/build/debug/swpasskeyctl"
PY="$ROOT/.venv/bin/python"
PROBE=${1:?p1|p2|p3|p4}
AAGUID=${2:-}
STORE=/tmp/swpk-probe.bin
SOCK=/tmp/swpk.sock
CTLSOCK=/tmp/swpk-probe.ctl

pkill -f "swpasskeyd --testing" 2>/dev/null || true
pkill -f "bridge_server.py" 2>/dev/null || true
sleep 0.6
rm -f "$SOCK" "$CTLSOCK" "$STORE" "$STORE.dek" /tmp/claim.txt

case "$PROBE" in
  p1)  ENV_CHAIN="SWPASSKEY_ATTEST_CHAIN=/tmp/abranch"; MODE=packed ;;
  p2)  MODE=self ;;
  p3)  MODE=packed; printf '42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3\n' > /tmp/claim.txt ;;
  p4)  MODE=packed; printf '%s\n' "${AAGUID:?p4 needs an AAGUID}" > /tmp/claim.txt ;;
  *)   echo "unknown probe $PROBE" >&2; exit 2 ;;
esac

env SWPASSKEY_HID_SOCKET="$SOCK" SWPASSKEY_ATTEST_MODE="$MODE" SWPASSKEY_LOG=warn \
    ${ENV_CHAIN:-} "$DAEMON" --testing --key-backend=software --store "$STORE" \
    --ctl-socket "$CTLSOCK" > /tmp/probe-daemon.log 2>&1 &
i=0; while [ ! -S "$SOCK" ]; do i=$((i+1)); [ $i -gt 50 ] && { echo "daemon failed"; tail -5 /tmp/probe-daemon.log; exit 1; }; sleep 0.1; done
"$CTL" --socket "$CTLSOCK" set-profile yubikey-5c-nfc-5.8 >/dev/null
echo "profile/attestation: $("$CTL" --socket "$CTLSOCK" attestation | cut -c1-160)"
[ -f /tmp/claim.txt ] && echo "claimed AAGUID: $(cat /tmp/claim.txt) (cert still says the profile's AAGUID)"
SWPASSKEY_BRIDGE_PIN=123456 SWPASSKEY_BRIDGE_AAGUID_FILE=/tmp/claim.txt \
  "$PY" "$ROOT/tools/browser-bridge/bridge_server.py" >> /tmp/bridge.log 2>&1 &
sleep 1.5
curl -s http://localhost:3000/health; echo " — $PROBE armed"
