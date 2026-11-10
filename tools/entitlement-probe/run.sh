#!/bin/sh
# Build, sign and run the minimal virtual-HID repro.
#
#   tools/entitlement-probe/run.sh
#
# Uses packaging/macos/embedded.provisionprofile (bundle ID taken from it, so the
# signature and the profile always agree) and the first keychain identity, or
# $SWPASSKEY_IDENTITY. Prints one verdict line, plus the kernel line that
# explains a refusal. Nothing outside a temporary directory is modified.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PROFILE=${SWPASSKEY_PROFILE:-$ROOT/packaging/macos/embedded.provisionprofile}
IDENTITY=${SWPASSKEY_IDENTITY:-}
WORK=${TMPDIR:-/tmp}/swpk-entitlement-probe
APP="$WORK/Probe.app"

[ -f "$PROFILE" ] || {
  echo "run.sh: no provisioning profile at $PROFILE" >&2
  echo "run.sh: set SWPASSKEY_PROFILE, or see packaging/macos/README.md" >&2
  exit 2
}

if [ -z "$IDENTITY" ]; then
  IDENTITY=$(security find-identity -v -p codesigning | sed -n 's/.*"\(.*\)".*/\1/p' | head -1)
fi
[ -n "$IDENTITY" ] || { echo "run.sh: no code-signing identity in the keychain" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$APP/Contents/MacOS"

# The bundle ID must equal the profile's application-identifier minus the team
# prefix, or AMFI will not bind the entitlements to this app.
security cms -D -i "$PROFILE" > "$WORK/profile.plist"
FULL_ID=$(plutil -extract 'Entitlements.com\.apple\.application-identifier' raw \
  -o - "$WORK/profile.plist")
TEAM=$(plutil -extract 'Entitlements.com\.apple\.developer\.team-identifier' raw \
  -o - "$WORK/profile.plist")
BUNDLE_ID=${FULL_ID#*.}

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
<key>CFBundleExecutable</key><string>probe</string>
<key>CFBundleName</key><string>probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
</dict></plist>
PLIST

cat > "$WORK/probe.entitlements" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.developer.hid.virtual.device</key><true/>
</dict></plist>
PLIST

clang++ -fobjc-arc -std=c++17 -O0 -o "$APP/Contents/MacOS/probe" "$HERE/probe.mm" \
  -framework Foundation -framework IOKit
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
codesign --force --options runtime --timestamp \
  --entitlements "$WORK/probe.entitlements" --sign "$IDENTITY" "$APP" >/dev/null 2>&1

echo "bundle id:    $BUNDLE_ID"
echo "team:         $TEAM"
echo "identity:     $IDENTITY"
echo "entitlement:  $(codesign -d --entitlements - "$APP" 2>&1 | grep -c hid.virtual.device) (1 = present in the signature)"
echo "profile:      $(grep -c hid.virtual.device "$WORK/profile.plist") (1 = profile grants it)"
echo

"$APP/Contents/MacOS/probe" | tee "$WORK/out.txt"
PID=$(sed -n 's/^pid: //p' "$WORK/out.txt")

if grep -q "device: CREATED" "$WORK/out.txt"; then
  echo
  echo "VERDICT: the kernel accepts the entitlement. A real HID key will enumerate."
  sleep 1
  exit 0
fi

echo
echo "VERDICT: IOHIDUserDevice refused. Kernel line:"
log show --last 2m --predicate 'process == "kernel"' 2>/dev/null |
  grep "pid $PID" | grep -i "MACF" | tail -1 | sed 's/^/  /'
echo
cat <<'EOS'
  "IOUC IOHIDResourceDeviceUserClient failed MACF" is the kernel's mandatory
  access control refusing the HID resource user client. It is not caused by this
  probe, by swpasskeyd, or by anything in the app's own code: the check runs
  before the app's entitlement-aware code path is reached.

  Attach this output (bundle id, team, and that kernel line) to an entitlement
  request at developer.apple.com/contact/request/system-extension/ and ask for
  the Virtual HID Device entitlement for the team.
EOS
exit 1
