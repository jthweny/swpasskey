#!/bin/sh
# Build a distributable swpasskeyd.dmg.
#
#   packaging/macos/make_dmg.sh <build-dir> ["Developer ID Application: …"] [release|debug] [--notarize <keychain-profile>]
#
# Steps: assemble + sign the .app (make_app.sh), stage it next to an
# /Applications symlink and a short read-me, then wrap the folder in a compressed
# DMG. Signed with a Developer ID and notarized, it opens on another Mac without
# a Gatekeeper warning.
#
# What it cannot do without your team: create a virtual HID device. That needs
# com.apple.developer.hid.virtual.device, which Apple grants per team, in a
# provisioning profile at packaging/macos/embedded.provisionprofile. Without it
# the app still installs, runs in the menu bar and says what is missing.
set -eu

BUILD_DIR=${1:?build dir (cmake --preset app)}
IDENTITY=${2:-}
MODE=${3:-release}
NOTARIZE="${SWPASSKEY_NOTARY_PROFILE:-}"
case "${4:-}" in
  --notarize) NOTARIZE=${5:?--notarize needs a notarytool keychain profile} ;;
  --notarize=*) NOTARIZE=${4#--notarize=} ;;
esac

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DIST=${SWPASSKEY_DIST:-$ROOT/dist}
APP_NAME=swpasskeyd.app
VOL_NAME="swpasskey"
DMG="$DIST/swpasskey.dmg"

mkdir -p "$DIST"
sh "$HERE/make_app.sh" "$BUILD_DIR" "$IDENTITY" "$MODE"
APP="$BUILD_DIR/$APP_NAME"
[ -d "$APP" ] || { echo "make_dmg: $APP missing" >&2; exit 1; }

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/swpk-dmg.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/volume"
cp -R "$APP" "$STAGE/volume/"
ln -s /Applications "$STAGE/volume/Applications"

cat > "$STAGE/volume/READ ME.txt" <<'EOF'
swpasskey — virtual FIDO2 security key

1. Drag swpasskeyd.app to Applications.
2. Open it once from Applications. The key icon appears in the menu bar; the app
   has no Dock icon and no window.
3. Menu bar icon → Settings… → enable "Open swpasskey at login" so the key is
   there after a restart (or leave it manual and start the app when you need it).
4. Compatibility Profile → pick the authenticator identity you want presented.
5. Add a security key on a website: choose "security key" when it asks, approve
   the swpasskey panel, and set a PIN when your browser offers it (user
   verification is required by many sites and needs a PIN).

The key is a software authenticator. Its private keys live in the Secure
Enclave, but the "touch" is the Approve panel, not a button. Attestation is a
self-signed certificate naming the modelled model, so sites that validate the
vendor certificate chain will still reject it.

Logs: ~/Library/Logs/swpasskey/swpasskeyd.log
Attestation details: swpasskeyctl attestation
Diagnostics: swpasskeyctl diagnostics ~/Desktop/diagnostics.json
EOF

cat > "$STAGE/volume/ATTESTATION.txt" <<'EOF'
swpasskey presents a modelled authenticator identity for compatibility testing.
AAGUIDs and certificate subject fields belong to third-party products. The
attestation certificate is self-signed, does not chain to any vendor root, and
this software is not FIDO-certified or affiliated with those vendors.
EOF

rm -f "$DMG"
hdiutil create -quiet -volname "$VOL_NAME" -srcfolder "$STAGE/volume" \
  -fs HFS+ -format UDZO -imagekey zlib-level=9 "$DMG"

if [ -n "$IDENTITY" ]; then
  codesign --force --timestamp --sign "$IDENTITY" "$DMG"
  echo "signed: $DMG"
fi

if [ -n "$NOTARIZE" ] && [ -n "$IDENTITY" ]; then
  echo "notarizing (this can take a few minutes)…"
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARIZE" --wait
  xcrun stapler staple "$DMG"
  xcrun stapler validate "$DMG"
else
  echo "note: not notarized; on another Mac run"
  echo "      xattr -d com.apple.quarantine /Applications/$APP_NAME"
fi

shasum -a 256 "$DMG"
echo "$DMG"
