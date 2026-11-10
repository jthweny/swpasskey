# What is left, split by who can do it

Written after the format matrix closed (rows 30-35). Two lists: what I finished without
help, and what needs LO.

## Done without needing anything from LO

1. **Transport claim now reaches the site.** `getInfo(0x04).transports` was hardcoded
   `["usb"]`; a 5C NFC advertises `["usb","nfc"]`. It is profile-driven now and piped
   through the bridge response into **both** shims. Verified end to end on our own RP
   (`localhost:8099`): `getTransports()` returns the daemon's claim, and the probe knob
   still overrides it. This mattered more than it looks: Chrome is never the CTAP client
   in this path, so `getTransports()` is whatever the shim says — the authenticator's real
   claim was invisible to the site until this was piped through.
2. **Registry golden repaired.** It still expected five profiles from before
   `5.7.4+`/enterprise/Securitag existed, and the AAGUIDs I had written into it were from
   memory rather than the registry. Fixed, plus a per-profile `transports` assertion.
   `123/123` tests pass.
3. **Anchor-door audit, closed.** Against MDS blob no. 299 (531 entries): every admitted
   AAGUID carries roots — 5C NFC 5.8 / 5.7.4+ / Security Key C NFC / enterprise = 6 each,
   5C NFC 5.7 = 1, Titan v2 = 2. **Zero** entries anywhere are identifier-only. The 30
   entries with no roots are all `NOT_FIDO_CERTIFIED` platform authenticators. So there is
   no admitted model whose anchor set a self-signed leaf could satisfy by picking a
   different AAGUID.
4. **`android-key` proven structurally sound.** python-fido2 has no verifier for it, so
   the 400 could have been malformation. `tools/browser-bridge/verify_android_key.py`
   parses the KeyDescription extension, proves `attestationChallenge == clientDataHash`,
   and verifies the signature over `authData‖cdh`. Our statement passes both.
5. **Signature provenance gap found and documented (row 34).** Both test formats sign
   with a key we generate, not the credential key the daemon holds. `fido-u2f` passed
   python-fido2 only because that verifier checks `cert.public_key()`. Corrected the
   earlier claim that it was "genuinely valid" — it is self-consistent, not
   spec-conformant, and a spec-strict verifier would refuse it on provenance alone.
6. **Attested what the server actually receives (row 35)**, read from the site's own
   serialiser: nine fields, `transports` and `authenticatorAttachment` the only
   client-chosen ones. Nothing else exists to vary.
7. **Both new formats submitted live**: `fido-u2f` → 400, `android-key` → 400. With
   `tpm` and `apple` already refused, all five formats are now measured.

## Needs LO

| what | why it needs you | effort |
| --- | --- | --- |
| **Sign in to `auth.openai.com`** — then I run: `transports:["usb","nfc"]` live probe, the three remaining AAGUID admissions (FIPS `fcc0118f`, Enhanced PIN `662ef48a`, 5C Nano consumer), and a `packed` baseline re-check | the auth session is a ~45-minute token; the enrolment endpoints return 409 without it | one login, then ~3 minutes of probes |
| **Reload the extension** (`chrome://extensions` → ⟳) **and ⌘R the OpenAI tab** | content scripts only inject on document load; the observer has never posted a sample, so the delayed-re-classification question is still unmeasured, and the new shim's real `transports` value only takes effect after this | two clicks |
| **Decide on the assertion test** — sign in with the virtual credential, then re-read the flags | it is a real login against the live account; whether classification is recomputed on use is unknown | your call |
| **~$29 Security Key C NFC**, or a support escalation citing TrustKey T110/T120 (compatible 24 Sep → ineligible 1 Oct) | the only paths that produce a vendor leaf signature, which row 33 shows is the actual gate | money or a ticket |
| **Optional disclosure**: their enrolment accepts `attStmt.sig` that does not match `x5c[0]` (row 3) | their call to fix; worth telling them | one email |

Anything not on either list has been measured, closed by evidence, or requires material
that does not exist publicly (a real device's leaf key).
