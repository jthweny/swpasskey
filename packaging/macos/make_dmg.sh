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

# Arguments are optional; the environment is the paste-safe path:
#   SWPASSKEY_IDENTITY        "Developer ID Application: Name (TEAMID)"
#   SWPASSKEY_NOTARY_PROFILE  notarytool keychain profile
#   SWPASSKEY_MODE            release (default) or debug
if [ "$#" -eq 0 ]; then
  cat >&2 <<'USAGE'
usage: packaging/macos/make_dmg.sh <build-dir> [identity] [release|debug] [--notarize <profile>]

  <build-dir>   a directory configured with `cmake --preset app`, e.g. build/app
  identity      optional "Developer ID Application: …"; also $SWPASSKEY_IDENTITY
  --notarize    notarytool keychain profile; also $SWPASSKEY_NOTARY_PROFILE

Example, no arguments beyond the build dir:
  SWPASSKEY_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
    packaging/macos/make_dmg.sh build/app
USAGE
  exit 2
fi

BUILD_DIR=$1
IDENTITY=${2:-${SWPASSKEY_IDENTITY:-}}
if [ -z "$IDENTITY" ]; then
  # No identity given: take the first codesigning identity in the keychain, so a
  # copy-pasted placeholder can never end up in a codesign invocation.
  IDENTITY=$(security find-identity -v -p codesigning |
    sed -n 's/.*"\(.*\)".*/\1/p' | head -1)
  if [ -n "$IDENTITY" ]; then
    echo "make_dmg: signing with: $IDENTITY" >&2
  else
    echo "make_dmg: no code-signing identity in the keychain; the DMG will be unsigned" >&2
  fi
fi
# A name that is not in the keychain (a stale export, a docs placeholder pasted
# in) fails here with the real list, before anything is assembled or signed.
if [ -n "$IDENTITY" ] &&
   ! security find-identity -v -p codesigning | grep -qF "\"$IDENTITY\""; then
  echo "make_dmg: no such code-signing identity: $IDENTITY" >&2
  echo "make_dmg: available identities:" >&2
  security find-identity -v -p codesigning | sed -n 's/.*"\(.*\)".*/  \1/p' >&2
  echo "make_dmg: unset SWPASSKEY_IDENTITY to use the first one automatically" >&2
  exit 2
fi

MODE=${3:-${SWPASSKEY_MODE:-release}}
NOTARIZE="${SWPASSKEY_NOTARY_PROFILE:-}"
case "${4:-}" in
  --notarize) NOTARIZE=${5:?--notarize needs a notarytool keychain profile} ;;
  --notarize=*) NOTARIZE=${4#--notarize=} ;;
esac

[ -d "$BUILD_DIR" ] || {
  echo "make_dmg: no build directory '$BUILD_DIR' (run: cmake --preset app)" >&2
  exit 1
}

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

# Notarization only accepts Developer ID Application signatures; an Apple
# Development certificate is for local installs, so say that here instead of
# letting notarytool reject the upload.
case "$IDENTITY" in
  "Developer ID Application"*) ;;
  "") ;;
  *)
    if [ -n "$NOTARIZE" ]; then
      echo "make_dmg: notarization needs a Developer ID Application identity" >&2
      echo "make_dmg: this machine has '$IDENTITY', which is fine for a local install" >&2
      exit 2
    fi
    ;;
esac

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
