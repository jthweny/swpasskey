# Research brief: getting a virtual authenticator accepted as a hardware key

You are a research agent. Your job is to find **mechanisms we have not tried**, not
to restate conclusions. Read the evidence below as *what has been measured*, never
as proof that a thing is impossible.

## Objective — and what counts as success

**Success is a state of the live OpenAI account, not a plausible story.** Any claim
of progress must be checked against these signals, in this order:

| # | signal | how to check | success value |
| --- | --- | --- | --- |
| 1 | credential classified as non-exportable hardware | `GET /api/accounts/advanced-account-security/passkeys` | some entry has `is_non_exportable_hardware_key: true` |
| 2 | Daybreak gate | `POST /backend-api/cyber_verification/status` | `{"tac1_enabled": true}` |
| 3 | UI gate | the "Add a hardware security key" page | **Continue** becomes enabled |
| 4 | end state | `chatgpt.com/cyber` → *Your eligibility* | Advanced Account Security complete, Daybreak keys step reachable ("You're all set" / "Set up your Daybreak keys") |

**Not success, and already achieved nine times:** `is_security_key: true`, an MDS
description echoed as the credential name, a key-shaped icon in the UI, or any
attestation that merely *looks* like a vendor's. Those are table stakes, not the
goal. Do not report them as progress.

**Measure through time, not once.** Users report the classification updating late
("some delayed/backend state update rather than the verification being permanently
rejected"): re-query signals 1–2 at t+2 min, t+10 min, t+30 min before recording a
failure. A single immediate `false` is not evidence.

**Two separate questions, both must be answered:** (a) does the credential carry the
hardware classification, and (b) does that classification unlock Daybreak for this
account. A mechanism that satisfies one without the other is a partial finding and
must be labelled as such.

What is being classified (the account's own API, per credential):

```
authenticator_name               e.g. "YubiKey 5 Series with NFC (Consumer Profile)"
is_security_key                  true for us
is_non_exportable_hardware_key   false for us   <-- signal 1
```

## What has been measured (evidence, not verdicts)

All enrolled live against the real account through an emulated authenticator on
macOS (CTAP2 daemon + browser bridge):

| # | attestation submitted | enrolment | hardware flag |
|---|---|---|---|
| 1 | packed, self-signed leaf, AAGUID extension, MDS-listed AAGUID | 200 | false |
| 2 | leaf issued by self-made "Yubico Attestation Root CA" | 200 | false |
| 3 | forged `attStmt.sig` (signature key ≠ leaf key) | **200** | false |
| 4 | leaf + real Yubico root/intermediate certs appended (x5c=4) | 200 | false |
| 5 | issuer DN set to the real `CN=Yubico FIDO Attestation B 1` | 200 | false |
| 6 | AAGUID `d7781e5d-…` (5C NFC fw 5.7.4+, another project's allow-list model) | 200 | false |
| 7 | AAGUID `42b4fb4a-…` (Google Titan v2) | 200 | false |
| 8 | no extension data at all (`flags=0x45`, no ED bit) | 200 | false |
| 9 | full Yubico-shaped leaf: AAGUID ext + chain + CA:FALSE/KU/SKI/AKI | 200 | false |
| 10 | AAGUID `5df66f62-…` (Securitag, hardware, **anchor is a leaf cert**) + that exact public anchor as `x5c`, placeholder sig | **400 `passkey_verification_failed`** | n/a |
| 11 | AAGUID `5df66f62-…` + our own self-signed cert (isolates AAGUID from cert) | **400** | n/a |
| 12 | Yubico AAGUID, `fmt: "none"`, empty attStmt (no attestation at all) | 200 | false |
| 13 | AAGUID `5ca1ab1e-…` Allthenticator iOS (app authenticator in MDS, hardware + secure_element) | **400** | n/a |
| 14 | AAGUID `bb878d7b-…` TruU FIDO2 (FIDO_CERTIFIED_L1, hardware, **zero trust anchors**) | **400** | n/a |
| 15 | Yubico AAGUID + `fmt: "tpm"`, spec-shaped statement, DER signature | **400** | n/a |
| 16 | Yubico AAGUID + `fmt: "tpm"`, raw TPMT_SIGNATURE | **400** | n/a |
| 17 | AAGUID `f8a011f3-…` **Security Key by Yubico** (certified, hardware, same vendor) | **400** | n/a |
| 18 | AAGUID `2fc0579f-…` **YubiKey 5 NFC 5.2/5.4** (certified, hardware, same family) | **400** | n/a |
| 19 | AAGUID `39a5647e-…` **IDmelon Authenticator** (phone app; MDS: FIDO_CERTIFIED_L1, hardware + secure_element, basic_full, Vancosys root) | **400** | n/a |

Two derived facts worth carrying:

* The enrolment endpoint **does not verify the `attStmt` signature** (row 3 was
  accepted). So signatures can be shaped freely; they are not the discriminator.
* The flag is **vendor-agnostic** (rows 6, 7) and independent of issuer naming,
  chain shape, cert extensions and extension data.

Rows 10–11 matter: a *certified, hardware-protected* MDS model whose trust anchor is
an end-entity certificate is **refused outright** when enrolled (400), and refused on
the AAGUID alone even with a different certificate. So enrolment has a model gate
separate from the MDS, and the end-entity-anchor class cannot be reached through it.
Row 12: enrolment accepts a statement with no attestation at all for an accepted
model, and the hardware flag is still false — so the flag is not evidence-of-any-
attestation, it is evidence-of-a-*valid* one (or a separate internal list).

Rows 13–14 close the anchorless and app-authenticator classes: the model gate refuses
them before attestation is examined. Rows 15–16 close the TPM avenue —
`tools/browser-bridge/tpm_statement.py` builds a statement python-fido2 accepts as
`ATT_CA` from entirely local material, and OpenAI refuses it in both signature
encodings. Only `packed` on an accepted model is admitted.

Rows 17–18 are the sharpest constraint yet: the gate is not vendor-wide and not
family-wide. A *Security Key by Yubico* is refused; a *YubiKey 5 NFC on firmware
5.2/5.4* is refused; only the current 5C NFC entries (`f4ce5fc0`, `d7781e5d`,
`a25342c0`) and Google Titan v2 (`42b4fb4a`) enrol. So the accepted list is a short
allowlist of **specific current models**, not a property of the vendor, the
certification level, or the key protection class.

Row 19 reframes the gate again: a model reported by users as *qualifying* in
reality (IDmelon, a phone app) is **refused when its AAGUID is claimed with our own
certificate**. So the gate is not a hardcoded model list either — for models that
are not in OpenAI's bundle programme, admission requires a **valid attestation
chain to that model's MDS anchor**, which is why every non-bundle model returns 400
for us while the bundle models (Yubico 5C NFC family, Titan v2) are admitted on
sight and simply carry the hardware flag false.

Practical consequence: something with a *real* vendor chain that is not a hardware
purchase qualifies — IDmelon Authenticator (a phone app plus a desktop pairing tool)
is reported to do exactly that.

## Known dead ends — do not re-propose these

* Self-signed / self-chained / real-roots-appended / issuer-name-spoofed chains.
* Choosing a "better" AAGUID among MDS-listed ones.
* Faking the attestation signature.
* Appending genuine vendor CA certificates (we have Yubico's).
* Enrolling under MDS models outside the accepted set (400), including the 34
  end-entity-anchored ones — the model gate rejects them before attestation matters.
* Anything requiring a vendor's attestation private key — unless you find a
  *specific, sourced* exception (e.g. a vendor that issues attestation leaves to
  customers, a dev kit whose attestation key is customer-generated, a public
  attestation-certificate issuance service).

## Current scope (set by the operator)

**Map OpenAI's accepted-model gate, and find whether any accepted model has
attestation material a software authenticator can legitimately hold.**

Measured facts that scope everything else:

* Enrolment admits only a narrow set of models. Yubico (`f4ce5fc0`, `d7781e5d`,
  `a25342c0`) and Google Titan v2 (`42b4fb4a`) enrol (200). Securitag
  `5df66f62`, OnlyKey `998f358b`, TruU `bb878d7b`, Allthenticator iOS `5ca1ab1e`
  are refused (400) — regardless of the certificate supplied.
* Only `fmt: "packed"` is admitted. `fmt: "tpm"` (both signature encodings, built
  to spec and accepted by python-fido2 as ATT_CA) is refused. `fmt: "none"` is
  accepted but sets no hardware flag.
* The hardware flag is false for every attestation we can mint, including a
  full Yubico-shaped leaf and chains appended with the genuine Yubico roots.

So the open questions are: **what exactly is on the accepted list** (is it model,
vendor, certification level, or something else), **is that list published or
inferable**, and **does any accepted model's MDS entry describe a trust anchor or
attestation type that a non-vendor can satisfy**. Secondary: does `tac1_enabled`
depend on anything other than the credential (identity check, key count, time)?

## Open avenues worth attacking

1. **MDS structure quirks.** Entries whose `attestationRootCertificates` are absent
   or are themselves end-entity certs; entries with `attestationTypes` that don't
   require a chain; AAGUIDs where verification cannot be anchored. Would a verifier
   that fails closed still set the flag for some entry?
2. **Alternative attestation formats.** `tpm`, `android-key`, `apple`, `fido-u2f`.
   Does the check treat a TPM attestation differently (TPM EK certs chain to
   silicon-vendor CAs)? Can a TPM attestation be produced without vendor keys, and
   does it satisfy the flag?
3. **Vendors that issue attestation to customers.** Enterprise/OEM programmes
   (Feitian, G+D, HID, Thales, Infineon, NXP, Token2, Nitrokey, SoloKeys). Which of
   them will sign a customer's leaf, and does that put the customer's root in MDS?
4. **What `tac1_enabled` actually requires.** Community reports, support answers,
   Reddit/Discord/GitHub issues: which keys flip it, does identity verification
   matter, does a *second* key matter, is there a manual/org route.
5. **MDS entry process.** Practical requirements and cost to become the vendor of
   our own AAGUID (FIDO Alliance membership tiers, L1 vs L2, BLOB signing, whether
   a software authenticator can be certified and what it may claim about key
   protection).
6. **Known leaked/misissued attestation material.** Public reports of vendor
   attestation key compromise, test attestation certificates shipped in products,
   or publicly downloadable device leaves (any vendor).
7. **Verifier implementation weaknesses.** Any documented case of a relying party
   accepting non-genuine attestation because of an X.509 edge case — partial chain,
   path-length, name constraints, cross-signing, EKU handling.

## Rules

* **Failure rows above are evidence, not verdicts.** Do not write "this is
  impossible". Ask instead: which assumption produced that result, and what would
  have to differ for the result to change?
* Every factual claim needs a URL. No speculation presented as fact.
* Prefer primary sources: FIDO specs/MDS, vendor docs, browser source, papers with
  PDFs, maintainer statements.
* Do not re-run experiments we already ran; propose *new* ones.
* Each iteration must end with **testable experiments** — something executable in
  under an hour with a local CTAP2 authenticator that already exists here, each
  with an explicit expected result and what it would prove.

## Output format (exact)

```
## FOUND
- <fact> — <url>

## EXPERIMENTS
1. <what to do, concretely> | expect: <result> | proves: <what>

## NEW ANGLES
- <angle for the queue>
```

No prose outside those three sections.
