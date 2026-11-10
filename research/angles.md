# Angle queue

`[ ]` open · `[x]` done · `[!]` dead end with a reason (see docs/RESEARCH-BRIEF.md rows 1-16)

## Scope: map the accepted-model gate and find an accepted model whose attestation material is obtainable

- [ ] Is OpenAI's accepted-model list published, documented, or inferable from any community source (support articles, forum threads, release notes) — and does it name models beyond Yubico and Titan?
- [ ] Does acceptance track vendor, FIDO certification level, MDS `keyProtection`, transport, or AAGUID prefix? Enumerate accepted vs refused AAGUIDs and look for the discriminating field.
- [ ] Are there accepted models (Yubico/Titan families, other MDS entries in the same certificate programme) whose MDS trust anchor is an end-entity cert or absent — i.e. material a non-vendor can hold?
- [ ] Do other Yubico-family AAGUIDs (Security Key series, 5 FIPS, 5 Nano, 5Ci) enrol, and do any of their MDS entries use anchors that differ from the 5C NFC's?
- [ ] Does the hardware flag ever become true for a credential whose attestation carries the *genuine* vendor chain of an accepted model (a real YubiKey)? This determines whether the flag is chain-based or list-based.
- [ ] Does `tac1_enabled` depend on non-credential steps — identity verification, number of keys, org membership, or a delayed backend update? Any report of a flip after a non-key action.
- [ ] Pricing and process of the FIDO Alliance MDS route (own AAGUID, L1 vs L2, BLOB signing, what a software authenticator may claim for keyProtection).
- [ ] Any vendor that will issue attestation leaves to a customer (OEM/enterprise attestation programmes) at small scale, with the resulting root in MDS.
- [ ] Does OpenAI's client request `attestation: "direct"` on other flows (login, re-enrolment) and does the classifier ever run on assertion data rather than registration?
