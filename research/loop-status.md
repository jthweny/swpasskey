# Loop status

Autonomous research loop. Reads docs/RESEARCH-BRIEF.md (scope + evidence) and
research/angles.md (queue). Findings land in research/findings/. New angles the
agent proposes are appended to the queue automatically.

## Measured so far (by the operator, before launch)

* Accepted models: `f4ce5fc0` (5C NFC consumer), `d7781e5d` (5.7.4+), `a25342c0`
  (5.7), `42b4fb4a` (Titan v2).
* Refused models: Securitag `5df66f62`, OnlyKey `998f358b`, TruU `bb878d7b`,
  Allthenticator iOS `5ca1ab1e`, **Security Key by Yubico `f8a011f3`**,
  **YubiKey 5 NFC 5.2/5.4 `2fc0579f`**.
* Only `packed` is admitted; `tpm` (both encodings) and `none`-with-evidence fail.
* Hardware flag false for every attestation shape, including full Yubico-shaped
  leaves and genuine Yubico roots appended.

## Log

- 08:39 Is OpenAI's accepted-model list published, documented, or inferable from any community sou -> 20261110-083704-is-openai-s-accepted-model-list-published-documented-or-infe.md
- 08:41 Does acceptance track vendor, FIDO certification level, MDS `keyProtection`, transport, or -> 20261110-083904-does-acceptance-track-vendor-fido-certification-level-mds-ke.md
- 08:45 Are there accepted models (Yubico/Titan families, other MDS entries in the same certificat -> 20261110-084148-are-there-accepted-models-yubico-titan-families-other-mds-en.md
- 08:47 Do other Yubico-family AAGUIDs (Security Key series, 5 FIPS, 5 Nano, 5Ci) enrol, and do an -> 20261110-084507-do-other-yubico-family-aaguids-security-key-series-5-fips-5-.md
- 08:48 Does the hardware flag ever become true for a credential whose attestation carries the *ge -> 20261110-084705-does-the-hardware-flag-ever-become-true-for-a-credential-who.md
- 08:50 Does `tac1_enabled` depend on non-credential steps — identity verification, number of keys -> 20261110-084851-does-tac1-enabled-depend-on-non-credential-steps-identity-ve.md
- 08:52 Pricing and process of the FIDO Alliance MDS route (own AAGUID, L1 vs L2, BLOB signing, wh -> 20261110-085020-pricing-and-process-of-the-fido-alliance-mds-route-own-aagui.md

## Operator notes

- 08:56 pressed "Set up Daybreak" on chatgpt.com/cyber: it demanded a **fresh email
  verification code** (step-up auth) before anything else. Next step needs the
  account owner to enter it; after that the precheck decides the key.
- IDmelon free tier does not qualify (operator tested); premium tier is reported to.
- 13 test credentials now on the account from these experiments.
- 08:55 Any vendor that will issue attestation leaves to a customer (OEM/enterprise attestation pr -> 20261110-085244-any-vendor-that-will-issue-attestation-leaves-to-a-customer-.md
- 08:56 Does OpenAI's client request `attestation: "direct"` on other flows (login, re-enrolment)  -> 20261110-085526-does-openai-s-client-request-attestation-direct-on-other-flo.md

## Brief state at this point

Rows 1-20 measured. Current model: admission = bundle-list OR valid chain; hardware =
hardware-list AND valid chain. Row 20 (real IDmelon credential enrolled, MDS-labelled,
hardware flag false) closed the "any real chain qualifies" hypothesis. Queue prioritised
toward: models on both lists with obtainable material, aggregating which models users
report as qualifying, and whether the hardware classification is re-evaluated over time.
- 08:58 IDmelon's metadata anchors to **Vancosys Root CA** and IDmelon is now part of HID Global — -> 20261110-085644-idmelon-s-metadata-anchors-to-vancosys-root-ca-and-idmelon-i.md
- 09:00 `attestationCertificateKeyIdentifiers` is a second attribution path in Metadata Statement  -> 20261110-085857--attestationcertificatekeyidentifiers-is-a-second-attributio.md
- 09:03 Yubico **enterprise attestation** is gated by an RP allowlist on the key itself (the `1ac7 -> 20261110-090057-yubico-enterprise-attestation-is-gated-by-an-rp-allowlist-on.md
- 09:06 Thetis being "sometimes works" suggests the accept set is not a clean model list at all bu -> 20261110-090325-thetis-being-sometimes-works-suggests-the-accept-set-is-not-.md
- 09:08 Whether `tac1_enabled` responds to *key count* and *removal of other passkeys* is still un -> 20261110-090607-whether-tac1-enabled-responds-to-key-count-and-removal-of-ot.md
- 09:11 Identify `f4ce5fc0` in the MDS blob (likely the firmware-5.8 AAGUID): if the newest AAGUID -> 20261110-090807-identify-f4ce5fc0-in-the-mds-blob-likely-the-firmware-5-8-aa.md
- 09:13 Ask Token2 directly (they provision a chosen AAGUID onto partner Java Card hardware, are F -> 20261110-091118-ask-token2-directly-they-provision-a-chosen-aaguid-onto-part.md
- 09:13 Pursue the "certification is the attestation key" fact from SoloKeys: build a Java Card /  -> 20261110-091305-pursue-the-certification-is-the-attestation-key-fact-from-so.md

## Pending: A-branch attestation test (armed, waiting on session)

Daemon is running with `SWPASSKEY_ATTEST_CHAIN=/tmp/abranch`: x5c = our leaf (issuer
name = the real anchor's subject `CN=Yubico FIDO Attestation A 1`) + the genuine
`Yubico FIDO Attestation A 1` + `Yubico Attestation Intermediate A 1` + `Yubico
Attestation Root 1`. This is the exact cert shape a real fw 5.7.4+ YubiKey 5C NFC
sends, except for the one signature we cannot produce.

Blocked: the account session expired again (409 invalid_state on /passkeys). When the
owner signs in: start the bridge, press Add, read the credential flags.
- 09:15 Cross-reference the Microsoft "Enforced attestation" column as a proxy list of models that -> 20261110-091335-cross-reference-the-microsoft-enforced-attestation-column-as.md
- 09:17 Check whether the verifier distinguishes `basic_full` from `basic_surrogate` / `AttCA`: ro -> 20261110-091507-check-whether-the-verifier-distinguishes-basic-full-from-bas.md
- 09:19 Test the reverse-AAGUID split: `authData` AAGUID = an accepted model while the cert's AAGU -> 20261110-091753-test-the-reverse-aaguid-split-authdata-aaguid-an-accepted-mo.md
- 09:22 Add a fresh-account control: enrol a *real* YubiKey (5C NFC, 5.8) on a new account and pol -> 20261110-091903-add-a-fresh-account-control-enrol-a-real-yubikey-5c-nfc-5-8-.md

## Resumed after the four live probes (rows 21-24)

P1 A-branch chain: 200, hardware false. P2 self-attestation: 200, false. P3 reverse
AAGUID split: 400 (cert AAGUID extension is cross-checked). P4 enterprise-profile
AAGUID 4599062e: 200, resolved by name, false. Account now holds 17 credentials, 0
flagged hardware, Continue disabled. Queue extended with list-change monitoring, the
extension-presence question, newer-unreleased AAGUIDs, and a search for any reported
*qualifying* software key.
- 10:00 **Enterprise attestation as a separate gate.** YubiKeys on EA‑capable firmware produce per -> 20261110-095803--enterprise-attestation-as-a-separate-gate-yubikeys-on-ea-ca.md
- 10:01 **RP trust-store vintage as an attack surface.** Cloudflare's case shows RPs pin/sync a sp -> 20261110-100055--rp-trust-store-vintage-as-an-attack-surface-cloudflare-s-ca.md
- 10:03 **OEM/attestation‑provisioning programmes** where the *customer* holds the attestation key -> 20261110-100115--oem-attestation-provisioning-programmes-where-the-customer-.md
- 10:06 **MDS portal economics for our own AAGUID** (FIDO membership tier, L1 vs L2, BLOB signing, -> 20261110-100341--mds-portal-economics-for-our-own-aaguid-fido-membership-tie.md
- 10:09 **Community-sourced negative list.** Since OpenAI publishes only exclusions (TrustKey T110 -> 20261110-100647--community-sourced-negative-list-since-openai-publishes-only.md
