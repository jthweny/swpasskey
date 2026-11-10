# Run it

Every block is a set of complete, short lines you can paste in one go. No line is
long enough to wrap, so a terminal can never split a command in half.

```sh
cd ~/VirtualYubi/swpasskey
```

Prerequisites, once per machine:

```sh
brew install cmake ninja
```

---

## 1. Build and package (unsigned)

```sh
cd ~/VirtualYubi/swpasskey
cmake --preset app
cmake --build build/app -j
packaging/macos/make_dmg.sh build/app
```

Output: `~/VirtualYubi/swpasskey/dist/swpasskey.dmg`.

Unsigned means: installs, runs, sits in the menu bar, but has no HID entitlement,
so it cannot pretend to be a USB device. Good for checking the pipeline.

## 2. Build the real thing (signed, with the HID entitlement)

You need three things that only your Apple account can provide:

1. **A signing identity** in the keychain. List them:

```sh
security find-identity -v -p codesigning
```

`make_dmg.sh` uses the first one automatically — there is no placeholder to edit.
If you set `SWPASSKEY_IDENTITY` yourself, copy the exact quoted name from that
output; the script checks it against the keychain and fails loudly if it does not
exist. A stale export from an older session is the usual cause, so:

```sh
unset SWPASSKEY_IDENTITY SWPASSKEY_NOTARY_PROFILE
```

`Apple Development:` signs for **this Mac** (install and run it locally).
`Developer ID Application:` is the one that can be distributed and notarized.
Notarization is refused with an Apple Development identity, on purpose.

2. **A provisioning profile whose App ID has the HID capability.** This is the
real gate; nothing here can create it.

   - developer.apple.com → Certificates, Identifiers & Profiles → **Identifiers**
   - register the explicit App ID `com.tangzixiang.swpasskey.daemon` (wildcards
     cannot carry restricted entitlements)
   - in that App ID's capability list, enable **HID Virtual Device**
     (`com.apple.developer.hid.virtual.device`). If it is not listed, it has to be
     granted to your team first — request it through Apple Developer Support; it
     is a restricted entitlement, not a self-service checkbox
   - **Profiles** → **+** → *macOS App Development* for that App ID → download

3. **The profile on disk:**

```sh
cp ~/Downloads/Your_Profile.provisionprofile \
   ~/VirtualYubi/swpasskey/packaging/macos/embedded.provisionprofile
```

Verify it actually grants the entitlement before building. `1` means yes, `0`
means the App ID does not have the capability:

```sh
security cms -D -i packaging/macos/embedded.provisionprofile |
  grep -c hid.virtual.device
```

Then build:

```sh
cd ~/VirtualYubi/swpasskey
cmake --preset app
cmake --build build/app -j
packaging/macos/make_dmg.sh build/app
```

Read what `make_app.sh` prints inside that. This line means the profile is not
granting the entitlement and the key will not enumerate:

```
warning: profile does not grant com.apple.developer.hid.virtual.device; stripping it
```

Notarize only with a Developer ID identity, and only if you plan to run the DMG
on another Mac:

```sh
xcrun notarytool store-credentials swpasskey-notary \
  --apple-id you@example.com --team-id TEAMID
export SWPASSKEY_NOTARY_PROFILE=swpasskey-notary
packaging/macos/make_dmg.sh build/app
```

## 3. Install and start

```sh
pkill -f /Applications/swpasskeyd.app/Contents/MacOS/swpasskeyd 2>/dev/null
DMG=~/VirtualYubi/swpasskey/dist/swpasskey.dmg
hdiutil attach "$DMG" -nobrowse -quiet -mountpoint /Volumes/swpasskey
cp -R /Volumes/swpasskey/swpasskeyd.app /Applications/
hdiutil detach /Volumes/swpasskey -quiet
open -a /Applications/swpasskeyd.app
sleep 4
pgrep -fl swpasskeyd
```

Key icon in the menu bar, no Dock icon, no window.

## 4. Check whether it is a USB key

Prints the HID entitlement line if the signature carries it:

```sh
codesign -d --entitlements - /Applications/swpasskeyd.app 2>&1 | grep hid
```

`iohid_created` means the device exists and Chrome picks it up live.
`hid_unavailable` means the entitlement is missing:

```sh
tail -n 40 ~/Library/Logs/swpasskey/swpasskeyd.log | grep -E "iohid|hid_"
```

Second opinion from the system, if the device is enumerating:

```sh
system_profiler SPUSBDataType | grep -A6 -i fido
```

## 5. Use it

Menu bar → **Compatibility Profile** → pick a model. On a website, choose
"security key", then click **Create Passkey** on the swpasskey panel (that is the
touch), and set a PIN when the browser offers one.

Same flow outside a browser:

```sh
python3 ~/VirtualYubi/swpasskey/tools/webauthn-probe/server.py > /tmp/probe.log 2>&1 &
sleep 1
open http://localhost:8080
```

Control the installed app:

```sh
swpasskeyctl=/Applications/swpasskeyd.app/Contents/MacOS/swpasskeyctl
$swpasskeyctl profiles
$swpasskeyctl set-profile yubikey-5c-nfc-5.8
$swpasskeyctl attestation
```

After a switch, wipe the credentials so the next registration looks factory-fresh:

```sh
$swpasskeyctl reset
```

Export what each registration actually sent:

```sh
$swpasskeyctl diagnostics ~/Desktop/diagnostics.json
open ~/Desktop/diagnostics.json
```

Which backend is holding the keys (this matters for the experiment):

```sh
$swpasskeyctl stats
```

## 6. Launch at login (optional)

Menu bar → **Settings…** → tick *Open swpasskey at login*. Or by hand:

```sh
PLIST=~/Library/LaunchAgents/com.tangzixiang.swpasskey.daemon.plist
cp packaging/macos/com.tangzixiang.swpasskey.daemon.plist "$PLIST"
launchctl bootstrap gui/$(id -u) "$PLIST"
```

## 7. Development run: no app, no entitlement, real CTAP

Debug preset, because `--testing` auto-approves the presence panel and only
exists in Debug builds:

```sh
cd ~/VirtualYubi/swpasskey
cmake --preset debug
cmake --build build/debug -j
python3 -m venv .venv
.venv/bin/pip install -q fido2
export SWPASSKEY_HID_SOCKET=/tmp/swpk.sock
export SWPASSKEY_CTL_SOCKET=/tmp/swpk-dev.sock
export SWPASSKEY_STORE=/tmp/swpk-dev.bin
export SWPASSKEY_LOG=warn
DAEMON=build/debug/swpasskeyd
$DAEMON --testing --key-backend=software > /tmp/swpk-dev.log 2>&1 &
sleep 2
.venv/bin/python tests/e2e/pyfido2_e2e.py /tmp/swpk.sock
```

Stop it:

```sh
pkill -f "swpasskeyd --testing"
```

## 8. Remove it

```sh
LABEL=com.tangzixiang.swpasskey.daemon
launchctl bootout gui/$(id -u)/$LABEL 2>/dev/null
pkill -f swpasskeyd
rm -rf /Applications/swpasskeyd.app
rm -f ~/Library/LaunchAgents/com.tangzixiang.swpasskey.daemon.plist
rm -rf ~/Library/Application\ Support/swpasskey
rm -rf ~/Library/Logs/swpasskey
```

## 9. When something is off

```sh
tail -f ~/Library/Logs/swpasskey/swpasskeyd.log
```

```sh
swpasskeyctl=/Applications/swpasskeyd.app/Contents/MacOS/swpasskeyctl
$swpasskeyctl stats
```

| What you see | What it means |
| --- | --- |
| menu bar: `No security key (not enumerating)` | no HID entitlement in the signature |
| `swpasskeyctl stats` says `"key_backend":"software"` on a signed build | `keychain-access-groups` missing, so the Secure Enclave probe failed; keys fall back to software, which is weaker custody but still registers |
| `Killed: 9` right after launch | the signature carries an entitlement the profile does not grant; re-run `make_app.sh` with the profile in place |
| `already_running` in the log | a second instance; the store `flock` refuses it |
| Chrome offers no key | the device is not enumerating, or the site requires a certified key and rejects the self-signed attestation |
| `make_dmg: no such code-signing identity: …` | `SWPASSKEY_IDENTITY` holds a stale or placeholder name; `unset` it |
| `make_dmg: no build directory` | run `cmake --preset app` first, from the repo root |
| `zsh: permission denied: build/app` | a wrapped line split the command; run the lines one at a time |
