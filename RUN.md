# Run it

Every block below is complete and copy-pasteable. Work from the repository root:

```sh
cd ~/VirtualYubi/swpasskey
```

Prerequisites (once per machine):

```sh
brew install cmake ninja
```

---

What state you are in right now, on this Mac: `swpasskeyd.app` is installed in
`/Applications` from the unsigned build, running, showing `No security key (not
enumerating)` in the menu bar. Section 8 removes it.

## 1. One block: build, package, DMG

```sh
cd ~/VirtualYubi/swpasskey && cmake --preset app && cmake --build build/app -j && packaging/macos/make_dmg.sh build/app "" release
```

You get `dist/swpasskey.dmg`. Unsigned, so this is the "does the pipeline work"
run — the app installs and starts, but without the HID entitlement it cannot
pretend to be a USB device and the menu bar says so.

## 2. One block: signed, notarized, installable DMG

Fill in your signing identity and notarytool profile first:

```sh
IDENTITY="$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application.*\)"/\1/p' | head -1)"
echo "$IDENTITY"
```

Then, with `packaging/macos/embedded.provisionprofile` in place (the profile must
grant `com.apple.developer.hid.virtual.device`, see `packaging/macos/README.md`):

```sh
cd ~/VirtualYubi/swpasskey && cmake --preset app && cmake --build build/app -j && packaging/macos/make_dmg.sh build/app "$IDENTITY" release --notarize swpasskey-notary
```

Create the notary profile once, if you have not:

```sh
xcrun notarytool store-credentials swpasskey-notary --apple-id you@example.com --team-id TEAMID --password "$(security find-generic-password -s AC_PASSWORD -w)"
```

## 3. Install and start it

```sh
hdiutil attach ~/VirtualYubi/swpasskey/dist/swpasskey.dmg -nobrowse -quiet -mountpoint /Volumes/swpasskey && cp -R /Volumes/swpasskey/swpasskeyd.app /Applications/ && hdiutil detach /Volumes/swpasskey -quiet && open -a /Applications/swpasskeyd.app
```

The key icon appears in the menu bar. No Dock icon, no window. Confirm it is
alive:

```sh
pgrep -fl swpasskeyd | head -3
```

## 4. Is it a USB key yet?

```sh
codesign -dv --entitlements - /Applications/swpasskeyd.app 2>&1 | grep -i "hid.virtual.device" && echo "ENTITLED" || echo "NO ENTITLEMENT: browsers will not see the key"
```

```sh
sleep 4; tail -n 40 ~/Library/Logs/swpasskey/swpasskeyd.log | grep -E "iohid_created|hid_unavailable" | tail -1
```

`iohid_created` means the device exists and Chrome will pick it up live. If you
see `hid_unavailable`, the bundle is not signed with the entitlement — the app is
running, the menu bar explains it, and no browser will see a device.

System-level second opinion (should list a FIDO usage page `0xF1D0` device whose
vendor matches your profile):

```sh
system_profiler SPUSBDataType 2>/dev/null | grep -B2 -A6 -i "FIDO"
```

## 5. Use it

Menu bar → **Compatibility Profile** → pick a model. Then add a security key on a
site: choose "security key", click **Create Passkey** on the swpasskey panel (that
is the touch), set a PIN when the browser offers one.

Watch the same flow outside a browser (starts the probe page in the background):

```sh
python3 ~/VirtualYubi/swpasskey/tools/webauthn-probe/server.py > /tmp/probe.log 2>&1 & sleep 1; open http://localhost:8080
```

Command line equivalent of the menu:

```sh
swpasskeyctl=/Applications/swpasskeyd.app/Contents/MacOS/swpasskeyctl
```

```sh
$swpasskeyctl profiles && $swpasskeyctl set-profile yubikey-5c-nfc-5.8 && $swpasskeyctl attestation
```

After switching, wipe the credentials so the next registration looks like a
factory-fresh key:

```sh
$swpasskeyctl reset
```

Export what each registration actually sent:

```sh
$swpasskeyctl diagnostics ~/Desktop/diagnostics.json && open ~/Desktop/diagnostics.json
```

## 6. Launch at login (optional)

Menu bar → **Settings…** → tick *Open swpasskey at login* (registers the bundled
LaunchAgent through `SMAppService`). Or do it by hand, without a login item:

```sh
cp ~/VirtualYubi/swpasskey/packaging/macos/com.tangzixiang.swpasskey.daemon.plist ~/Library/LaunchAgents/ && launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.tangzixiang.swpasskey.daemon.plist
```

## 7. Development run: no app, no entitlement, real CTAP

Drives the real daemon loop over a Unix socket, no HID device, no signing. Good
for verifying attestation and CTAP behaviour end to end. `--testing` auto-approves
the presence panel and only exists in the Debug build, hence `--preset debug`.

```sh
cd ~/VirtualYubi/swpasskey
cmake --preset debug && cmake --build build/debug -j
python3 -m venv .venv && .venv/bin/pip install -q fido2
rm -f /tmp/swpk.sock
SWPASSKEY_HID_SOCKET=/tmp/swpk.sock SWPASSKEY_LOG=warn build/debug/swpasskeyd --testing --key-backend=software --store /tmp/swpk-dev.bin --ctl-socket /tmp/swpk-dev.sock > /tmp/swpk-dev.log 2>&1 &
sleep 2
.venv/bin/python tests/e2e/pyfido2_e2e.py /tmp/swpk.sock
```

Stop it:

```sh
pkill -f "swpasskeyd --testing"
```

## 8. Uninstall

```sh
launchctl bootout gui/$(id -u)/com.tangzixiang.swpasskey.daemon 2>/dev/null; pkill -f swpasskeyd; rm -rf /Applications/swpasskeyd.app; rm -f ~/Library/LaunchAgents/com.tangzixiang.swpasskey.daemon.plist; rm -rf ~/Library/Application\ Support/swpasskey ~/Library/Logs/swpasskey
```

## 9. When something is off

```sh
tail -f ~/Library/Logs/swpasskey/swpasskeyd.log
```

```sh
swpasskeyctl=/Applications/swpasskeyd.app/Contents/MacOS/swpasskeyctl; $swpasskeyctl stats
```

| What you see | What it means |
| --- | --- |
| menu bar: `No security key (not enumerating)` | no HID entitlement in the signature; nothing a rebuild without the profile can fix |
| `swpasskeyctl stats` shows `"key_backend":"software"` on a signed build | the `keychain-access-groups` entitlement is missing, so the Secure Enclave probe failed and keys fall back to software. Registration still works; key custody is weaker. |
| `Killed: 9` right after launch | signature carries an entitlement the provisioning profile does not grant; re-run `make_app.sh` with the profile present |
| `already_running` in the log | a second instance; the store `flock` refuses it |
| Chrome offers no key | the device is not enumerating, or the site requires a certified key and rejects the self-signed attestation |
| `make_dmg.sh: build/app/swpasskeyd.app missing` | wrong working directory, or the app preset was not built |
