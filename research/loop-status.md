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

