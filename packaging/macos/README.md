# macOS: build, sign and ship `swpasskey.dmg`

The app is a background agent: no Dock icon, no window, a key icon in the menu
bar, and a virtual USB FIDO2 device that Chrome, Safari and `libfido2` treat like
a plugged-in security key.

Three of the four steps below need credentials only you have (your team, your
Developer ID certificate, your provisioning profile). Nothing in this repository
contains them, and nothing needs to be committed for the build to work.

---

## 0. The one thing Apple has to grant

`IOHIDUserDevice` — the API that fabricates a USB HID device out of thin air — is
gated by a restricted entitlement:

```
com.apple.developer.hid.virtual.device
```

It is not in the standard Developer ID profile. It is granted **per team**, on
request, usually after explaining what the device is for (driver development,
hardware emulation, accessibility, test tooling). Request it from your Apple
Developer account's "Certificates, Identifiers & Profiles → Identifiers" page
(enable the capability on the App ID), or through Apple Developer Support if it
is not listed for your account.

Then download the provisioning profile for that App ID and drop it here:

```
packaging/macos/embedded.provisionprofile
```

`make_app.sh` reads it, keeps only the restricted entitlements the profile
actually grants, and substitutes `$(AppIdentifierPrefix)` with your team ID. If
the profile does not grant the HID entitlement it strips it and warns:

```
warning: profile does not grant com.apple.developer.hid.virtual.device; stripping it
```

With it stripped the app still installs and runs, and the menu bar says
`No security key (not enumerating)` with the reason — browsers will not see a
device until the grant is in place.

## 1. Build

Run these **from the repository root** (the directory holding
`CMakePresets.json`), not its parent:

```sh
cd /path/to/swpasskey

brew install cmake ninja        # the presets use the Ninja generator
cmake --preset app
cmake --build build/app -j
```

Use the `app` preset: it links OpenSSL statically, because the hardened runtime
refuses to load a Homebrew `libcrypto` signed by another team. The resulting
binary depends only on system frameworks — check with
`otool -L build/app/swpasskeyd.app/Contents/MacOS/swpasskeyd`.

Homebrew's `libcrypto.a` is built for the current macOS, so linking against a
`CMAKE_OSX_DEPLOYMENT_TARGET` of 14.0 emits `was built for newer 'macOS'
version` warnings. Harmless for running on this Mac; to distribute to older
systems, configure with `-DCMAKE_OSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion)`
or build OpenSSL from source for the oldest target you support.

## 2. Sign, bundle, wrap in a DMG

```sh
IDENTITY="$(security find-identity -v -p codesigning \
  | sed -n 's/.*"\(Developer ID Application.*\)"/\1/p' | head -1)"

packaging/macos/make_dmg.sh build/app "$IDENTITY" release
```

Output: `dist/swpasskey.dmg` (small, ~600 KB) plus its SHA-256. Add notarization
so a fresh Mac does not warn:

```sh
xcrun notarytool store-credentials swpasskey-notary \
  --apple-id you@example.com --team-id TEAMID --password <app-specific password>

packaging/macos/make_dmg.sh build/app "$IDENTITY" release --notarize swpasskey-notary
```

The DMG contains `swpasskeyd.app`, a symlink to `/Applications`, and a short
read-me. Unsigned builds still produce a DMG — useful for testing the packaging —
but you must clear the quarantine bit yourself:

```sh
xattr -d com.apple.quarantine /Applications/swpasskeyd.app
```

## 3. Install and run

1. Open the DMG, drag **swpasskeyd** to Applications.
2. Launch it from Applications once. The key icon appears in the menu bar. macOS
   will ask for nothing (no admin rights, no system extension).
3. Menu bar → **Settings…** → *Open swpasskey at login* registers the bundled
   LaunchAgent through `SMAppService`, so the key is present after a reboot.
   System Settings may ask you to allow it under *General → Login Items*.
4. Menu bar → **Compatibility Profile** → pick the identity you want presented.
   The USB device re-enumerates with the new VID/PID/product strings.

The per-user state lives in `~/Library/Application Support/swpasskey/`:
`credentials.bin` (encrypted, DEK in the login keychain), `serial`,
`compat-identity`, `attestation.key` (0600), `diagnostics.json`. The log is
`~/Library/Logs/swpasskey/swpasskeyd.log`.

## 4. What happens in the browser

Chrome and Safari enumerate FIDO HID devices through `IOHIDManager` and pick up a
newly appeared device live — no browser restart, no flag. When the site asks for a
security key:

1. The site runs `navigator.credentials.create()` with
   `authenticatorAttachment: "cross-platform"` (OpenAI Daybreak additionally wants
   `userVerification: "required"` and `attestation: "direct"`).
2. The browser lists the devices it can see; swpasskey appears as a USB security
   key. Choosing it sends `authenticatorMakeCredential` over CTAPHID.
3. The **swpasskey panel** appears ("Create a passkey for …?") — that is this
   key's "touch". Click **Create Passkey**.
4. If the browser asks for a PIN (it will, because user verification is
   required), set one: the daemon answers `PIN_NOT_SET` on the first attempt and
   the browser offers to create a PIN, which is stored in `credentials.bin`.
5. The response carries `fmt: "packed"` with an `x5c` certificate and the profile's
   AAGUID. The site now decides whether that counts as a hardware key.

To watch the same flow with the raw values in front of you:

```sh
python3 tools/webauthn-probe/server.py     # then open http://localhost:8080
swpasskeyctl diagnostics ~/Desktop/diagnostics.json
swpasskeyctl attestation
```

## 5. Troubleshooting

| Symptom | Cause |
| --- | --- |
| Menu bar says `No security key (not enumerating)` | Entitlement missing or stripped. Check `codesign -dv --entitlements - /Applications/swpasskeyd.app` for `com.apple.developer.hid.virtual.device`. |
| App starts and exits immediately | `~/Library/Logs/swpasskey/swpasskeyd.log`; usually a signing/profile mismatch (AMFI kill shows as `Killed: 9`). |
| Two key icons | The LaunchAgent is running and you also launched the app. Quit one; the store's `flock` prevents a second instance. |
| Browser never offers the key | The device is not enumerating (see above), or the site requires a certified key and rejects the self-signed attestation — that is the experiment, not a bug. |
| `IOHIDUserDeviceCreate failed` after re-signing | The profile grants the HID entitlement but the app was signed with `swpasskeyd.debug.entitlements` without the profile present. Re-run `make_app.sh` with the profile in place. |

## 6. Uninstall

```sh
launchctl bootout gui/$(id -u)/com.tangzixiang.swpasskey.daemon 2>/dev/null
rm -rf /Applications/swpasskeyd.app
rm -rf ~/Library/Application\ Support/swpasskey ~/Library/Logs/swpasskey
security delete-generic-password -s swpasskey 2>/dev/null || true
```

Deleting the app does not un-register the login item; turn it off in
**Settings…** first, or bootout the agent as above.
