# Browser bridge

Runs the WebAuthn ceremony for a page out of `swpasskeyd` instead of out of a USB
HID device. The relying party receives a **real** CTAP2 attestation — the selected
profile's AAGUID, a packed statement with an `x5c` certificate — produced by its
own page, in its own origin, from its own challenge.

This is the answer to the macOS kernel gate: `IOHIDUserDevice` needs an
entitlement Apple has not granted (see `docs/entitlement-request.md`), but nothing
about the relying party's decision depends on a USB device existing. It reads the
attestation object.

```
page JS  →  navigator.credentials.create()  →  bridge.js (in the page)
                                                    │  fetch to 127.0.0.1:8100
                                              bridge_server.py
                                                    │  CTAP2 over a Unix socket
                                              swpasskeyd  (socket transport)
```

## Verified in a real browser

Chrome, on a page requesting `attestation: "direct"`, `cross-platform`,
`residentKey: required`, `userVerification: required` — the same options as the
target site. What the page received:

```
fmt=packed  x5c=1  aaguid=f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5
subject=/C=SE/O=Yubico AB/OU=Authenticator Attestation/CN=YubiKey 5C NFC
AAGUID extension=f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5
flags=UP,UV,AT   BE=0  BS=0   signCount=1   credProps.rk=true   transports=usb
```

and the discoverable sign-in that followed: `flags=UP,UV`, `signCount=2`, user
handle returned.

## Run it

One command does all of it — daemon, profile, bridge, and a health check that
refuses to continue if the socket never appeared:

```sh
tools/browser-bridge/start.sh                      # yubikey-5c-nfc-5.8, PIN 123456
tools/browser-bridge/start.sh google-titan-v2      # another identity
```

It prints the profile, the attestation subject and the bridge URL, and appends to
`/tmp/bridge.log` so a restart keeps the previous ceremony.

By hand, for reference:

**1. The daemon, socket transport** (no HID device, so no entitlement needed;
`--testing` auto-approves the presence panel and exists only in Debug builds):

```sh
cd ~/VirtualYubi/swpasskey
cmake --preset debug
cmake --build build/debug -j
python3 -m venv .venv
.venv/bin/pip install -q fido2
export SWPASSKEY_HID_SOCKET=/tmp/swpk.sock
export SWPASSKEY_LOG=warn
build/debug/swpasskeyd --testing --key-backend=software \
  --store /tmp/swpk-bridge.bin --ctl-socket /tmp/swpk-bridge.sock &
sleep 2
```

**2. Pick the identity under test** (this is what the relying party classifies):

```sh
build/debug/swpasskeyctl --socket /tmp/swpk-bridge.sock set-profile yubikey-5c-nfc-5.8
build/debug/swpasskeyctl --socket /tmp/swpk-bridge.sock attestation
```

**3. The bridge**, with a PIN for user verification. The daemon has none by
default, so the bridge sets this one on first use:

```sh
SWPASSKEY_BRIDGE_PIN=123456 .venv/bin/python tools/browser-bridge/bridge_server.py --hid-socket /tmp/swpk.sock
```

## The port is not a detail: the page's CSP decides

The first attempt against the real site fails like this:

```
Connecting to 'http://127.0.0.1:8100/webauthn/create' violates the following
Content Security Policy directive: "connect-src 'self' blob: … http://localhost:3000 …"
```

The shim runs inside the page, so `connect-src` applies to its `fetch`. That
policy allows **`http://localhost:3000`** and not `127.0.0.1`, so the bridge
listens on that exact origin by default:

```sh
SWPASSKEY_BRIDGE_PIN=123456 .venv/bin/python tools/browser-bridge/bridge_server.py --hid-socket /tmp/swpk.sock
# -> [bridge] listening on http://localhost:3000/
```

For a site with a different rule, read its `connect-src` and set both:
`--port N` on the server and `window.__SWPK_BRIDGE = "http://localhost:N"` before
the shim (or edit `BRIDGE` in `bridge.js`).

`tools/webauthn-probe/server.py --csp` serves the probe page with a matching
policy, so this class of failure is reproducible without the real site.

## PRF

Sites that use passkeys for encryption (ChatGPT's enrollment does) ask for the
**PRF** extension. The bridge maps it onto the daemon's CTAP `hmac-secret`
extension, which is the mechanism PRF is built on:

* `create` with `extensions.prf` → sends `hmac-secret: true`, and reports
  `prf.enabled: true`. The authData carries the ED flag, as on a real key.
* `get` with `prf.eval.first` (and optionally `.second`) → salts are
  `SHA-256(eval)`, evaluated under the UV credRandom, decrypted, and returned as
  `prf.results.first` / `.second` — 32-byte `ArrayBuffer`s, stable for a given
  salt.

## Point it at the real site

1. Open the site's sign-in page and get to the screen that offers **add a security
   key** (not "this device" / not "passkey in this browser").
2. Open DevTools → Console. Paste the entire contents of
   `tools/browser-bridge/bridge.js`. It prints
   `[swpasskey bridge] WebAuthn routed to http://127.0.0.1:8100`.
3. Choose the security-key option and press the site's own **Continue / Add
   security key** button.
4. The site's `navigator.credentials.create()` reaches the bridge; the daemon
   produces the attestation; the site posts it to its backend, which is where the
   classification happens.

Watch the bridge terminal: one line per ceremony with the AAGUID, format and
`x5c` count. `swpasskeyctl diagnostics` has the full record.

Run the bridge with `>>` rather than `>`: a restart then keeps the earlier
ceremonies instead of truncating the only evidence of what just failed.

## When the page shows nothing and the bridge returns 500

The page's own error handling usually swallows the reason, so the bridge prints it
twice: as an `[bridge] ERROR …` line in its terminal, and as
`console.error("[swpasskey bridge] …")` in the page. Refresh the console filter to
`swpasskey` if the site floods it (Datadog `rum` 403s are normal noise).

| bridge says | meaning |
| --- | --- |
| `CTAP 0x31 (PIN_INVALID)` | `SWPASSKEY_BRIDGE_PIN` is not the daemon's PIN. Delete the store file and restart both, or set the PIN to match. |
| `CTAP 0x34/0x35 (PIN_NOT_SET)` | no PIN on the daemon and none was passed; set `SWPASSKEY_BRIDGE_PIN`. |
| `CTAP 0x15 (LIMIT_EXCEEDED)` | the site's user handle is over 64 bytes, or the store is full. No hardware key would accept it either. |
| `CTAP 0x19 (CREDENTIAL_EXCLUDED)` | this key already registered for that account; the site is refusing a duplicate. |
| `CTAP 0x27 (OPERATION_DENIED)` | presence was declined — remove `--testing` and click the panel. |
| `bridge unreachable at http://localhost:3000` | the bridge is not running, or is on another origin than the page's CSP allows. |
| `no daemon socket at /tmp/swpk.sock` | the daemon is not running or was started without `SWPASSKEY_HID_SOCKET`; `start.sh` avoids this. |

Start clean, which removes the PIN and duplicate-credential cases in one move:

```sh
rm -f /tmp/swpk-bridge.bin /tmp/swpk-bridge.bin.dek
```

## What is real, and what is not

Real: the CTAP2 ceremony, the credential key (Secure Enclave / TPM / software,
depending on the daemon), the signature, the attestation certificate, the AAGUID,
the `clientDataJSON` (the page's own origin and challenge, hashed by the bridge
exactly as a browser would), `authData` flags, the signature counter.

Not real: there is no USB device. The credential object reports
`authenticatorAttachment: "cross-platform"`, `getTransports() → ["usb"]` and
`credProps.rk: true` so the page sees what a plugged-in key reports, but that is a
description, not a device. Anyone who inspects the machine's USB tree sees
nothing, and `iohid` never runs.

Consequences worth knowing before you read a verdict from this:

* It measures the **relying party's classifier**, which is the question. It does
  not prove the same key would pass a browser-level check, an MDM policy, or a
  USB attestation collector.
* If a site hides its security-key option behind
  `PublicKeyCredential.getClientCapabilities()` or conditional UI, the shim does
  not patch those yet; say so and it can be added.
* Some consoles block pasted code (`self-XSS` warning): type `allow pasting`, then
  paste. Pasting into the console is not subject to the page's CSP; injecting with
  `fetch(...).then(eval)` is, so prefer the paste for strict sites.
* The page talks to `http://127.0.0.1:8100`, a loopback address, which browsers
  treat as trustworthy even from an HTTPS page. Nothing leaves the machine.

## Limits of the shim

* One ceremony at a time is fine; the bridge opens a fresh CTAPHID channel per
  request, so parallel tabs work.
* `navigator.credentials.create/get` are replaced on the page's
  `navigator.credentials` object. A page that captured a reference to the original
  before injection keeps using it; inject before its scripts run
  (`Page.addScriptToEvaluateOnNewDocument`) or reload after pasting.
* Assertions honour `allowCredentials` and discoverable selection; conditional
  mediation (autofill) is not implemented.
* `response.getPublicKey()` returns `null`; sites that read the SPKI at
  registration (rare) would notice. The COSE key is in the attestation object
  anyway.
* PRF needs the credential to have been created with `hmac-secret`, i.e. through
  this bridge. Credentials registered before that will return no PRF output.
