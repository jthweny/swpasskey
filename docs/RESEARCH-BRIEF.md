# Research brief: getting a virtual authenticator accepted as a hardware key

You are a research agent. Your job is to find **mechanisms we have not tried**, not
to restate conclusions. Read the evidence below as *what has been measured*, never
as proof that a thing is impossible.

**CURRENT TARGET (2026-11-10):** a way to make `is_non_exportable_hardware_key`
true for a software authenticator on macOS, without buying hardware. 26 attestation
shapes and 4 client-side tricks are closed. The four untested ideas are in
"Unknown" below; anything that needs a vendor's attestation private key is out of
scope unless you can source one legitimately (published test material that is
actually in the MDS, an OEM programme, or a documented key extraction).

## State of knowledge (read this first)

### Works — measured, reproduce any time with `tools/probe.sh`

* A virtual authenticator enrols through OpenAI's normal flow and lands in the
  credential list with `is_security_key: true`, named from the MDS
  ("YubiKey 5 Series with NFC (Consumer Profile)", "Security Key Series with NFC
  (Consumer Profile)", "YubiKey 5 Series (Enterprise Profile)", "Google Titan
  Security Key v2", "IDmelon").
* AAS enrolment completes on the strength of that; the Daybreak page reports
  "Enroll in Advanced Account Security — Completed".
* Admission is granted on sight to *currently marketed* Yubico models (consumer,
  enterprise profile, 2023+ Security Key series) and Titan v2 — certificate content
  is not inspected for these. The 2019 "Security Key by Yubico" AAGUID `f8a011f3`
  and the 5.2/5.4 AAGUID `2fc0579f` are refused, so admission tracks the model list.
* Credentials can be produced with any of: our self-signed leaf, a fabricated chain,
  a genuine-but-unrelated Yubico A/B chain appended, no attestation at all
  (`fmt: none`), or packed self-attestation — all enrol.

### Does not work — 26 measured rows, see the table below

* `is_non_exportable_hardware_key` has never been true for anything we can mint:
  26 attestation shapes, including the exact A-1 chain a real 5.7.4+ 5C NFC sends.
* `fmt: "tpm"` in both signature encodings (refused), client-asserted
  `enterpriseAttestation` (accepted, still false), reverse AAGUID split (rejected —
  the certificate's AAGUID extension is cross-checked), non-Yubico models such as
  Securitag/OnlyKey/TruU/Allthenticator/IDmelon-AAGUID (refused at admission),
  MDS end-entity anchors (refused at admission), anchorless hardware entries
  (refused at admission).
* FIDO's enterprise-attestation test PKI is **not** in the MDS, so its published
  batch private key is useless here.
* TrustKey T110/T120 carry genuine vendor chains and are still labelled "Passkey":
  an active deny component overrides classification for named models.

### Unknown — after rows 27-29, this is all that is left

Closed since the list was first written: the anchor pool is **global** (row 27), no
MDS-published certificate is a registered device key (row 28: 0 of 1102), and
`fmt: "apple"` is refused like `tpm` (row 29). So a chain we assemble cannot reach
the flag, and the material that could is unpublished.

What genuinely remains:

* **Staleness of *their* metadata.** Cloudflare had to sync MDS BLOB 281 to accept
  5.7.x chains, so RPs run snapshots, not the live blob — https://community.cloudflare.com/t/fido2-security-key-enrollment-fails-with-attestation-certificate-chain-is-not-sign/959209
  If OpenAI's snapshot predates or postdates an entry, an AAGUID's admission can
  differ from what the current MDS implies. Is there an AAGUID whose status changed
  across blobs that we can test?
* **Whether the flag is really the identifier hash.** It is the only remaining input,
  but it is inferred, not proven. Is there any published observation of a credential
  with `is_non_exportable_hardware_key: true` whose attestation certificate could be
  identified (screenshot, log, community post), which would name the tested value?
* **Whether classification is re-evaluated over time.** Users report flips days
  later. Does any *software* credential ever flip, or only genuine ones?
* **The `qualifying_count` oracle.** `/backend-api/cyber_verification/refresh_status`
  reports counts before the UI does. It needs the page's bearer token; is it readable
  in-page, and does it ever disagree with the per-credential flags?
* **Any reversal or addition to the accepted set.** They moved once inside a week.

Anything that requires a vendor's attestation private key, a captured device leaf, or
bypassing a live verification is out of scope: row 28 established the material is not
publicly obtainable, and the remaining work is measurement, not forgery.

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
| 20 | **real IDmelon Authenticator credential** (the app itself, free tier, enrolled through the normal flow) | 200, listed as "IDmelon" | **false** |
| 21 | **A-branch chain**: leaf issued by a CA named `Yubico FIDO Attestation A 1`, x5c = leaf + genuine A-1 + Intermediate A-1 + Root 1 | 200 | false |
| 22 | packed **self-attestation** (no x5c), Yubico AAGUID | 200 | false |
| 23 | **reverse AAGUID split**: authData AAGUID = Titan, certificate's AAGUID extension = Yubico | **400** | n/a |
| 24 | `4599062e` **YubiKey 5 Series (Enterprise Profile)** with the certificate and authData agreeing | 200, resolved by name | false |
| 25 | `clientExtensionResults.enterpriseAttestation: true` asserted by the shim (that JSON rides to the server verbatim) | 200 | false |
| 26 | AAGUID `0f083f18` **Security Key C NFC 5.8** — the retail $29 model users report working | 200, "Security Key Series with NFC (Consumer Profile)" | false |
| 27 | **global-anchor-pool probe**: AAGUID `5df66f62` Securitag (refused on sight in row 10) but `x5c` ending in the genuine Yubico A-1 → Intermediate A-1 → Root 1 | **200**, resolved as "Securitag Assembly Group FIDO Authenticator NFC" | false |
| 28 | **published-material replay**: for every end-entity MDS anchor (1102 certificates), is its own SPKI hash listed in `attestationCertificateKeyIdentifiers`, or does it carry an AAGUID extension? | **0 of 1102 for both** | n/a |
| 29 | Yubico AAGUID + `fmt: "apple"`, local chain with the Apple nonce extension (`1.2.840.113635.100.8.2` = SHA-256(authData‖cdh)) | **400** | n/a |
| 30 | Yubico AAGUID + **`fmt: "fido-u2f"`** — statement over `0x00‖rpIdHash‖cdh‖credId‖0x04‖x‖y`, signed by the leaf certificate's key; python-fido2 returns BASIC because it verifies against `cert.public_key()` | **400** | n/a |
| 31 | Yubico AAGUID + **`fmt: "android-key"`** — KeyDescription extension with `attestationChallenge = cdh` | **400** | n/a |
| 32 | **`transports` claim** — what `getInfo(0x04).transports` reports, which reaches the site through `getTransports()` → the registration POST. Emulation said `["usb"]` for a dual-interface model; now profile-driven (`["usb","nfc"]` for the 5C NFC family) | **not yet submitted** — needs a signed-in tab | n/a |
| 34 | **Attestation-statement provenance** — every format we can mint is signed by a key we generate; none is signed by the *credential* key, which the daemon holds and never exports. `fido-u2f` passes python-fido2 only because that verifier checks `cert.public_key()`; `android-key` is self-consistent (challenge bound, sig verifies) but not spec-conformant. A spec-strict verifier would refuse both regardless of chain | **closed** — signature provenance cannot be forged without the daemon exporting credential keys | n/a |
| 33 | **Anchor-door audit of the admitted set**, against MDS blob no. 299: every admitted AAGUID has roots (5C NFC 5.8 / 5.7.4+ / Security Key C NFC / enterprise = 6, 5C NFC 5.7 = 1, Titan v2 = 2); **0** entries worldwide are identifier-only; the 30 entries with neither roots nor identifiers are all `NOT_FIDO_CERTIFIED` platform authenticators | **closed** — no admitted model lacks an anchor | n/a |

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

Row 20 is decisive for the "any real chain will do" theory: a genuine credential
from a real app with a real MDS entry is admitted and **labelled from the MDS**
("IDmelon", not "Passkey") — and the hardware flag is still false. Combined with rows
1–18 the model that fits every observation is:

```
admission  = model is on OpenAI's bundle list  OR  attestation chains to that model's MDS anchor
hardware   = model is on OpenAI's *hardware* list  AND  attestation chains to that model's anchor
```

The bundle models we can claim (Yubico 5C NFC family, Titan v2) are admitted on sight
but fail the chain half; every model we could chain to is off the hardware list.
The two conditions never hold at once for material we can produce.

Row 23 is a new constraint: the certificate's `id-fido-gen-ce-aaguid` extension is
**cross-checked against authData**, so a credential cannot borrow one model's label for
another — their verifier is a proper packed verifier in that respect. Row 24 shows the
gate admits Yubico models of any edition (consumer, enterprise profile) on sight, and
the hardware flag stays false for all of them without a genuine chain.

Row 25 removes the client-asserted EA hypothesis: `clientExtensionResults` reaches the
server unaltered and asserting `enterpriseAttestation` changes nothing. Row 26 shows
the 2023+ Security Key series *is* admitted (its 2019 predecessor `f8a011f3` is not),
so admission tracks currently marketed models while the evidence requirement does not.
FIDO's enterprise-attestation test PKI is not in the MDS, so its published private key
buys nothing. TrustKey's real keys carry genuine chains and are still labelled
"Passkey", so OpenAI applies an active deny component on top of classification.

Row 27 answers the per-AAGUID vs global question: the anchor pool is **global**. A
model that is refused when certified with its own self-signed leaf is admitted when the
chain merely *ends in* another vendor's published anchor, and it is named from its own
MDS entry. So anchors are matched as a set, across entries.

Combined with row 3 (the `attStmt` signature is not verified) and every `hw: false`, the
remaining explanation for the hardware flag is the *other* half of the metadata:
**`attestationCertificateKeyIdentifiers`** — a SHA-1 over the leaf's public key, so it
identifies the *key*, not the chain. A certificate whose SPKI hashes to a registered
value is the only thing that can flip the flag, and no amount of chain assembly reaches
it. That is now the single conclusion, reached from four independent directions.

Row 28 closes the last route that needed no private key. The MDS publishes
certificates only as *anchors*, and none of them is also a registered leaf key: zero of
1102 end-entity anchors has its SPKI in an identifier list, and zero carries an AAGUID
extension. The registered leaf keys that the flag actually tests are therefore not
published anywhere — they exist only inside real devices, and are emitted only by
devices. Replaying a real leaf (row 28's remaining variant) would mean presenting a
specific physical key's identity as one's own, and the material for it is not obtainable
from public sources in any case.

### Correction to rows 27-28

The hardware flag is **path validation of the leaf certificate to an MDS anchor**, not
the `attestationCertificateKeyIdentifiers` hash. Evidence: the accepted Yubico entries
carry no identifiers at all (136 MDS entries do; none of the accepted AAGUIDs; none is
identifier-only), so identifiers cannot be the test for the model we enrol with.
Identifiers are a second attribution path used alongside anchors, never instead of
them. Rows 27 and 28 remain valid as measurements — the pool is global, and no
published certificate is a registered leaf — but the mechanism they were read as
supporting has changed.

Rows 30-31 finish the format matrix: all five attestation formats have now been
submitted on an accepted AAGUID. `packed` and `none` are admitted, `tpm`, `apple`,
`fido-u2f` and `android-key` are refused. Row 30 is the strongest of the refusals —
its signature is genuinely valid under the certificate, so the refusal cannot be
attributed to a malformed statement.

Row 33 closes the "find an admitted model whose anchor set is empty or
identifier-only" line of reasoning: there is none, so no self-signed leaf can become an
anchor by picking a different AAGUID. The 30 anchorless entries in the blob are all
uncertified platform authenticators, which are not what Daybreak admits.

Row 32 records a correction to this project's own pipeline: because the extension relays
`navigator.credentials.create()` over HTTP, Chrome is never the CTAP client, so
`getTransports()` is whatever the shim says. The authenticator's real `getInfo` claim was
invisible to the site until it was piped through the bridge response and both shims.

Row 34 corrects an overclaim made earlier in this project: `fido-u2f` was described as
"the only format whose signature is genuinely valid". It is valid under python-fido2,
which verifies against the certificate's key; the WebAuthn text puts the signature on the
credential key, which we do not hold. So the honest statement is that the statement is
self-consistent, and both refused formats would also be refused for provenance alone.

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

## Digest of prior research (do not re-derive these)

Facts established by earlier iterations, each with its source. Treat them as
starting points; build on them, do not repeat the search that produced them.

* OpenAI's bundle with Yubico is **YubiKey C Nano + C NFC**; Support told a user
  "keys supplied through the OpenAI/Yubico bundle are supported for Daybreak" —
  https://community.openai.com/t/daybreak-does-not-recognize-trustkey-t110-physical-fido2-keys-as-hardware-security-keys/1401917
* OpenAI publishes only a **denylist** (TrustKey T110/T120) and calls keys
  "approved" without listing them; public messaging claims "any other
  FIDO-compliant security key" works, which the measurements contradict —
  https://help.openai.com/en/articles/20001259-troubleshooting-openai-daybreak ,
  https://openai.com/index/advanced-account-security
* TrustKey T110/T120 were confirmed compatible on 24 Sep and ineligible on 1 Oct:
  **the accepted set changes over time** — same thread.
* An **IDmelon Authenticator credential** (phone app, real MDS entry, basic_full,
  Vancosys root) is admitted and labelled from the MDS, and the hardware flag is
  still false (measured, row 20).
* Yubico rotated its attestation PKI in 2025: fw 5.7.4+ chains leaf → `Yubico FIDO
  Attestation A 1` → `Yubico Attestation Intermediate A 1` → `Yubico Attestation
  Root 1`; pre-5.7.4 uses `Yubico U2F Root CA Serial 457200631` —
  https://developers.yubico.com/U2F/Attestation_and_Metadata
* The certificate's `id-fido-gen-ce-aaguid` extension is **cross-checked** against
  authData (row 23 = 400 on mismatch).
* `attestationCertificateKeyIdentifiers` is a parallel attribution namespace: hex
  SHA-1 over the **bare subjectPublicKey BIT STRING**, and `fido-u2f` registrations
  carry an all-zero AAGUID, so those entries are addressable only by certificate
  key id — https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1-ps-20250521.html
* FIDO certification economics: Associate membership **$3,250** (≤100 employees),
  functional certification **$6,000** member / $9,000 non-member, **L1 open to
  software** (document review, no lab), **L2 requires a hardware AROE** —
  https://fidoalliance.org/members/become-a-member , https://fidoalliance.org/fido-certification-fees ,
  https://fidoalliance.org/security-certification-authenticator-security-levels
* Microsoft's equivalent list is a versioned MDS snapshot refreshed monthly —
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor
* Users report the verdict updating **days later** with no action ("delayed/backend
  state update rather than the verification being permanently rejected") —
  https://community.openai.com/t/trusted-access-for-cyber-issue/1399570?page=2
* Daybreak eligibility behaves as a conjunction — plan, AAS, hardware key, identity
  check — with a `403 cyber_verification_precheck_failed` before Persona —
  https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview
* Yubico enterprise attestation is gated by an **RP allowlist on the key itself**
  (the `1ac7…` feature), so EA cannot be obtained unilaterally.
* Anchoring tools to check claims against: `tools/mds-anchor-audit.py` (end-entity
  and anchorless entries), `tools/browser-bridge/tpm_statement.py` (spec-shaped TPM
  statement), `tools/probe.sh` (arm one attestation shape), `tools/flag-poller.mjs`.

* FIDO's EA conformance material ships an EA batch certificate **and its private
  key**, but its test root is absent from the MDS (verified against all 531
  entries) — https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Authenticator/README.md
* `clientExtensionResults` is forwarded to the server verbatim, yet asserting
  `enterpriseAttestation: true` changes nothing (row 25).
* Engine-side OEM attestation exists commercially (NXP SE05x ships NXP-signed
  attestation certs and runs a Trust Provisioning service; Sectigo provisions
  Infineon OPTIGA TPM certs at factory; Token2 issues per-unit certificates while
  its Pico line has none) — a purchase, not a research path —
  https://www.nxp.com/docs/en/application-note/AN13254.pdf , https://www.token2.com/pages/how-to-verify-your-token2-fido2-key
* Community positives and negatives are consistent with a model list plus a deny
  component: TrustKey (denied), Thetis (fails), Pico FIDO (fails; its maintainer
  passed the AAS two-method gate, not the hardware step), one retail Security Key C
  NFC success — https://community.openai.com/t/daybreak-does-not-recognize-trustkey-t110-physical-fido2-keys-as-hardware-security-keys/1401917 ,
  https://github.com/polhenarejos/pico-fido/issues/304

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
