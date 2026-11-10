# What we can still do

Extracted from 20 measured attestation experiments and ~25 research iterations.
Everything here is either (a) a probe left to run, (b) a purchase, or (c) closed.

## The gate, as measured

```
admission  = model is in OpenAI's bundle list   OR  attestation chains to that model's MDS anchor
hardware   = model is on OpenAI's hardware list AND attestation chains to that model's anchor
```

* Bundle models: **YubiKey C Nano + C NFC** (5C NFC family AAGUIDs `f4ce5fc0`,
  `d7781e5d`, `a25342c0`; C Nano `4599062e`) and Google **Titan v2**.
* A real IDmelon credential is admitted and labelled from the MDS
  ("IDmelon") — and the hardware flag is still false, so admission ≠ hardware.
* Only `packed` is admitted; `tpm` is refused in both signature encodings.
* TrustKey T110/T120 were confirmed compatible on 24 Sep and declared ineligible on
  1 Oct — **the list changes over time**, so a negative today is not permanent.

## Probes left to run (free, need a logged-in session)

| # | probe | what it settles | cost |
| --- | --- | --- | --- |
| P1 | **A-branch chain** — leaf whose issuer name is the real anchor's subject, plus genuine `Yubico FIDO Attestation A 1` → `Intermediate A 1` → `Root 1` | whether their verifier does path validation or anchor-fingerprint matching | 1 click, armed |
| P2 | **Yubico AAGUID + self-attestation** (`packed`, no `x5c`, sig by credential key) | the "uncertainty"/self branch of WebAuthn §8.2, never tested on an accepted model | 1 click |
| P3 | **Reverse AAGUID split** — `authData` AAGUID = accepted model, cert's `id-fido-gen-ce-aaguid` = different/no value | whether the cert extension is cross-checked | 1 click |
| P4 | **C Nano / FIPS AAGUIDs** — `4599062e`, `fcc0118f`, `79f3c8ba`, `662ef48a` | whether other bundle models are admitted on sight and whether any reports hardware without a chain | 4 clicks |
| P5 | **Delayed re-classification** — poll `/passkeys` for an hour | users report the verdict flipping days later with no action | automatic |

All five are implemented or armed; they need one login, then they run in about
three minutes.

## Purchases that actually work

| option | cost | likelihood | notes |
| --- | --- | --- | --- |
| **YubiKey Security Key C NFC v5.8** | $25–29 | certain | the bundle model; users confirm it clears Daybreak |
| YubiKey C Nano | ~$50 | certain | the other bundle model |
| IDmelon Authenticator **premium** | subscription | low | free tier enrols but is not flagged hardware; premium would have to change the attestation *and* put IDmelon on the hardware list |
| FIDO Alliance certification of this fork | ~$9.3k + months | none for Daybreak | L1 is open to software ($6k + $3,250 membership, document review, no lab); L2 requires a hardware AROE, so software is excluded structurally. Even with an MDS entry we would land where IDmelon is: admitted, labelled, not hardware. |
| OEM attestation (vendor signs our leaf; Token2 reportedly provisions a chosen AAGUID) | 4–5 figures | low | the resulting chain terminates at *that* vendor's root, so the credential reads as their model, which is not on OpenAI's hardware list either |

## Closed

20 attestation shapes, all refused or flagged false: self-signed (with and without
the AAGUID extension), fabricated chains, forged signatures, genuine Yubico CA
certificates appended (both B and A branches pending P1), issuer-name spoofing,
`fmt: none`, `fmt: tpm` (DER and raw), MDS end-entity anchors, anchorless entries,
app authenticators, and three non-bundle AAGUID families refused outright.

## Honest summary

Every remaining free probe tests *how* the chain is checked. None of them can supply
the signature that is being checked, so the expected outcome is another four rows of
`false`. The two things that can actually change the answer are a **$29 key** (a
bundle model with a genuine chain) or **OpenAI changing the list**, which they have
already done once inside a week.
