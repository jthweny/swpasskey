# Compatibility fork: security-key presentation

This fork of [`madeye/swpasskey`](https://github.com/madeye/swpasskey) exists for
one experiment: make a software authenticator present itself the way a
commercial USB security key does, and observe how a relying party classifies the
result. The target observer is **OpenAI Daybreak**, which requires a
"compatible physical FIDO2 hardware security key" and rejects passkeys, but the
implementation is generic — any RP that inspects attestation can be probed.

Success is *not* "the registration completed". Success is the RP's own backend
reporting `passkeys.qualifying_count >= 1` for the account. Everything below is
built to make that measurement possible and to explain whatever answer comes
back.

> **What this is not.** It is not a YubiKey, not a FIDO-certified authenticator,
> and not hardware. Private keys never leave the key backend (Secure Enclave / TPM
> / software) but a same-uid process can use them without a physical button. The
> attestation certificate is ours, not the vendor's. Nothing here should be used
> where a certified key is required for real security.

---

## 1. What changed relative to upstream

| Area | Upstream | This fork |
| --- | --- | --- |
| Identity | one fixed AAGUID, `0x1209:0xF1D0`, "swpasskey" strings | `CompatProfile` registry: stock plus four modelled commercial keys, selectable at runtime |
| AAGUID | compile-time constant | from the selected profile, in `getInfo` and in attested credential data |
| USB identity | fixed | VID/PID/bcdDevice/manufacturer/product/serial from the profile, re-enumerated on switch |
| Attestation | packed **self**-attestation, no `x5c` | packed attestation **with `x5c`**: a profile-aware certificate, AAGUID extension, self-signed leaf; optional real chain |
| `getInfo` | no `uv`; `clientPin` only when set | `uv: true`, `plat: false`, `rk: true`, `clientPin` always present |
| `uv: true` requests | rejected with `INVALID_OPTION` | accepted: `PIN_NOT_SET` without a PIN (browser offers to create one), `PUAT_REQUIRED` with a PIN but no token |
| Diagnostics | counters only | per-registration JSON: identity, attestation, certificate subject/issuer, BE/BS/UP/UV, signCount, RP, credential id, timestamp |
| Test page | none | `tools/webauthn-probe/` (localhost HTTPS/HTTP, `attestation: "direct"`, cross-platform, rk, uv) |

Unchanged: Secure Enclave / TPM key backends, PIN/UV handling, resident
credentials, CTAP2.1 command set, CTAP1/U2F, HID transport, storage format,
presence prompts, menu bar, control socket protocol (extended, not altered).

## 2. Profiles

| id | AAGUID | USB | Attestation subject |
| --- | --- | --- | --- |
| `stock-swpasskey` (default) | `6fb1dfdd-51c0-43a0-a6f2-f74812cbf8fb` | `1209:f1d0` | `C=US, O=swpasskey, OU=Authenticator Attestation, CN=swpasskey Software Authenticator` |
| `yubico-security-key-c-nfc-5.8` | `0f083f18-4105-43a8-ad69-24e812e38141` | `1050:041f` | `C=SE, O=Yubico AB, OU=Authenticator Attestation, CN=Security Key by Yubico` |
| `yubikey-5c-nfc-5.8` | `f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5` | `1050:0407` | `C=SE, O=Yubico AB, OU=Authenticator Attestation, CN=YubiKey 5C NFC` |
| `yubikey-5c-nfc-5.7` | `a25342c0-3cdc-4414-8e46-f4807fca511c` | `1050:0407` | same, firmware 5.7 |
| `google-titan-v2` | `42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3` | `18d1:9470` | `C=US, O=Google LLC, OU=Authenticator Attestation, CN=Titan Security Key v2` |

PIDs and `iProduct` strings are modelled from the vendors' published USB tables.
They are cosmetic: no relying party sees the HID descriptor. The AAGUID and the
attestation certificate are what matter.

Two AAGUIDs for the same YubiKey model (5.7 and 5.8) are deliberate: if the
classifier is keyed on MDS *entry* rather than on *model*, the older firmware
should behave differently from the newer one. That single comparison is worth
more than any amount of certificate cosmetics.

## 3. Attestation, honestly

`makeCredential` now returns:

```
fmt:     "packed"
attStmt: { alg: -7, sig: <ES256 over authData || clientDataHash>,
           x5c: [ <DER leaf> ] }
```

The leaf is generated once per profile from a batch key stored 0600 at
`<data-dir>/attestation.key`, with:

* subject from the profile (C/O/OU/CN, as FIDO packed attestation requires),
* `basicConstraints: critical, CA:FALSE`, `keyUsage: critical, digitalSignature`,
* SKI and AKI (equal, since it is self-signed),
* `id-fido-gen-ce-aaguid` (`1.3.6.1.4.1.45724.1.1.4`) carrying the profile AAGUID,
* P-256 key, 20-year validity, random 128-bit serial.

The leaf is **self-signed**: `subject == issuer`, and it does not chain to any
vendor root. `swpasskeyctl attestation` prints the subject, issuer and the
SHA-256 of the leaf so a record can be tied to a certificate.

**What that cannot do.** FIDO MDS metadata for a real model carries
`attestationCertificateKeyIdentifiers` — SHA-1 digests of the vendor's
attestation certificate public key — and RPs that validate attestation chains
compare the leaf against those, or verify the chain to a vendor root. A
self-signed leaf fails both regardless of how convincing its subject is. If a
classification succeeds with this fork, the RP is using something weaker:
AAGUID lookup, `keyProtection` in the metadata, or an allowlist of models. That
is a useful finding, and it is the finding the experiment is designed to
surface.

### Optional real chain

```
leaf.pem    leaf certificate, DER-in-PEM, leaf first
leaf.key    P-256 private key for leaf.pem (PEM)
chain.pem   intermediates/root, optional
```

```sh
SWPASSKEY_ATTEST_CHAIN=/path/to/dir swpasskeyd ...
```

When present, `x5c` is the shipped chain verbatim and `attStmt.sig` is produced
by `leaf.key`; the generated batch key is not used. This is the path to exact
reproduction of a captured chain and to testing hypothesis 2 (chain validation)
separately from hypothesis 1 (AAGUID → MDS).

## 4. Running it

### Build a DMG

```sh
cd swpasskey                       # the repo root: CMakePresets.json lives here
brew install cmake ninja           # presets use Ninja
cmake --preset app
cmake --build build/app -j

IDENTITY="$(security find-identity -v -p codesigning \
  | sed -n 's/.*"\(Developer ID Application.*\)"/\1/p' | head -1)"
packaging/macos/make_dmg.sh build/app "$IDENTITY" release --notarize <profile>
# → dist/swpasskey.dmg
```

The DMG holds `swpasskeyd.app` (menu-bar agent, no Dock icon, launches at login
once enabled) plus a symlink to `/Applications`. Drag it over, open it once, pick
a profile from the menu bar. Chrome picks the device up live — no restart — and
the daybreak "add a security key" sheet lists it as a USB key; the Approve panel
*is* the touch, and the browser creates a PIN when it asks for user verification.

`packaging/macos/README.md` covers the parts that need **your** team: the
`com.apple.developer.hid.virtual.device` grant (per team, on request), the
provisioning profile at `packaging/macos/embedded.provisionprofile`, Developer ID
signing and notarization. Without the grant the app still installs and runs, and
the menu bar says `No security key (not enumerating)` with the reason instead of
exiting.

Never commit the profile, the certificates or the keys; `.gitignore` blocks them.

### Select a profile

Menu bar → **Compatibility Profile** → pick a model. The daemon persists the
choice to `<data-dir>/compat-identity`, switches the AAGUID immediately,
regenerates the attestation leaf for the new subject, and re-enumerates the USB
device. The menu then offers **Reset Credentials**:

```sh
swpasskeyctl profiles
swpasskeyctl set-profile yubikey-5c-nfc-5.8
swpasskeyctl reset                      # factory reset (asks for approval)
swpasskeyctl attestation
swpasskeyctl diagnostics ~/Desktop/daybreak-diagnostics.json
```

Resetting matters when the target backend has seen the account before: a
credential created under one AAGUID cannot be re-attested, so the account has to
be given a fresh registration to judge.

### Probe page

```sh
python3 tools/webauthn-probe/server.py            # http://localhost:8080
python3 tools/webauthn-probe/server.py --tls      # https + self-signed cert
```

Open the page in Chrome, press **Register security key**, approve the presence
prompt (and set a PIN when Chrome asks — user verification is required, and the
key answers `PIN_NOT_SET` until one exists). The page decodes the attestation
object and the server appends it to `registrations.jsonl`.

### The actual measurement

1. `swpasskeyctl reset` and pick the profile under test.
2. Register on the Daybreak target with `attestation: "direct"`.
3. Read the backend verdict for the account (`passkeys.qualifying_count`,
   `passkeys.eligible`, whatever the response exposes).
4. `swpasskeyctl diagnostics` → the exact AAGUID, flags, certificate subject and
   leaf digest that were sent.
5. Switch profile, reset, repeat. One account, one variable per run.

## 5. Reading the result

| Observation | Reading |
| --- | --- |
| Qualifies with `yubikey-5c-nfc-5.*`, not with stock | AAGUID-driven (MDS lookup and/or allowlist). |
| Qualifies with a YubiKey AAGUID, not with `google-titan-v2` | Model/batch allowlist, or a per-vendor rule. |
| Qualifies with 5.8, not 5.7 (same model) | The MDS entry, not the model, is the key. |
| Still a passkey with a valid AAGUID and `x5c` | Chain or key-identifier validation is in play; try the real-chain path. |
| Still a passkey with a real chain | The classifier looks at something this fork does not present (vendor-specific CTAP vendor commands, FIDO certification flags, `certifications` in `getInfo`, transport metadata). |

The last row is a legitimate outcome. A negative result with a real chain, a real
AAGUID and BE/BS clear is strong evidence that the check is not merely
"is there an attestation certificate".

## 6. Diagnostics format

```json
{
  "generated": "2026-01-31T09:12:04.115Z",
  "count": 1,
  "records": [{
    "timestamp": "2026-01-31T09:12:03.481Z",
    "profile": "yubikey-5c-nfc-5.8",
    "profile_name": "YubiKey 5C NFC (5.8)",
    "aaguid": "f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5",
    "rp_id": "auth.openai.com",
    "credential_id": "d1fb…",
    "attestation_format": "packed",
    "attestation_source": "self-signed",
    "x5c_present": true,
    "x5c_len": 1,
    "x5c_subject": "CN=YubiKey 5C NFC,OU=Authenticator Attestation,O=Yubico AB,C=SE",
    "x5c_issuer": "CN=YubiKey 5C NFC,OU=Authenticator Attestation,O=Yubico AB,C=SE",
    "x5c_leaf_sha256": "c01f…",
    "flags": {"up": true, "uv": true, "be": false, "bs": false, "at": true, "ed": false},
    "sign_count": 1,
    "key_backend": "se"
  }]
}
```

Bounded to 512 records, rewritten on every registration at
`<data-dir>/diagnostics.json` (0600). No private key material, no PIN material.

## 7. Tests

```sh
ctest --test-dir build/app --output-on-failure     # unit
python3 tests/e2e/pyfido2_e2e.py /tmp/swpk.sock    # full CTAP over the socket transport
```

`tests/e2e/pyfido2_e2e.py` verifies with `fido2`'s `PackedAttestation` verifier
that the statement classifies as `BASIC` (a chain), that the leaf is self-signed,
that the AAGUID extension matches `authData`, and that `attStmt.sig` verifies
against the leaf's public key. `tests/attestation_test.cpp` covers the same in
C++ plus the vendor-chain path.

## 8. Ground rules

* MIT, upstream copyright preserved (see `NOTICE`).
* No certificate, private key or provisioning profile is ever committed; see
  `.gitignore`.
* The modelled vendor names exist to describe the experiment, not to claim
  certification. Do not ship this or present its attestation as a vendor key.
