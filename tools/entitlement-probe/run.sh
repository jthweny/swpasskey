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

rm -rf "$WORK"
mkdir -p "$APP/Contents/MacOS"
security cms -D -i "$PROFILE" > "$WORK/profile.plist"

# Sign with the certificate the profile authorises, not just the first one in
# the keychain: a Developer ID profile rejects an Apple Development signature.
PROFILE_CN=$(python3 "$HERE/cert-cn.py" "$WORK/profile.plist" | head -1)
if [ -z "$IDENTITY" ]; then
  IDENTITY=$(security find-identity -v -p codesigning |
    sed -n 's/.*"\(.*\)".*/\1/p' | grep -F "$PROFILE_CN" | head -1)
fi
if [ -z "$IDENTITY" ]; then
  echo "run.sh: the profile is issued for \"$PROFILE_CN\"," >&2
  echo "run.sh: which is not a code-signing identity in this keychain. Available:" >&2
  security find-identity -v -p codesigning | sed -n 's/.*"\(.*\)".*/  \1/p' >&2
  exit 2
fi

# The bundle ID must equal the profile's application-identifier minus the team
# prefix, or AMFI will not bind the entitlements to this app.
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

if grep -q ProvisionedDevices "$WORK/profile.plist"; then
  PROFILE_KIND="development (has a registered-device list)"
else
  PROFILE_KIND="distribution-style (no device list)"
fi

echo "profile path: $PROFILE"
echo "profile name: $(plutil -extract Name raw -o - "$WORK/profile.plist")"
echo "profile uuid: $(plutil -extract UUID raw -o - "$WORK/profile.plist")"
echo "created:      $(plutil -extract CreationDate raw -o - "$WORK/profile.plist")"
echo "expires:      $(plutil -extract ExpirationDate raw -o - "$WORK/profile.plist")"
echo "kind:         $PROFILE_KIND"
echo "bundle id:    $BUNDLE_ID"
echo "team:         $TEAM"
echo "identity:     $IDENTITY"
echo "entitlement:  $(codesign -d --entitlements - "$APP" 2>&1 | grep -c hid.virtual.device) (1 = present in the signature)"
echo "grant:        $(grep -c hid.virtual.device "$WORK/profile.plist") (1 = profile grants it)"
echo

GRANT=$(grep -c hid.virtual.device "$WORK/profile.plist" || true)
if [ "$GRANT" = "0" ]; then
  cat <<'EOS'
VERDICT: this profile does not contain com.apple.developer.hid.virtual.device, so
no signature made with it can create a virtual HID device.

  A Developer ID profile is issued without that entitlement: Apple only puts it in
  development profiles, and even there the kernel refuses it until the team is
  granted the entitlement. That is the point of the entitlement request, not
  something a different profile type can work around.
EOS
  exit 1
fi

"$APP/Contents/MacOS/probe" > "$WORK/out.txt" 2>&1
STATUS=$?
cat "$WORK/out.txt"
PID=$(sed -n 's/^pid: //p' "$WORK/out.txt")

if [ -z "$PID" ]; then
  echo
  echo "VERDICT: the probe did not reach main() (exit $STATUS). AMFI rejects a"
  echo "         signature whose restricted entitlements the profile does not grant."
  exit 1
fi

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
