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
