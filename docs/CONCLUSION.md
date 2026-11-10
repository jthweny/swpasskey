# Conclusion: what was measured

Twenty-nine attestation variants, a global-anchor-pool probe, four formats, and a
full audit of the FIDO MDS. One file, because the result is a boundary rather than
a technique.

## The gate, as measured

```
admission      model is openly marketed by Yubico/Google  OR  attestation carries
               an anchor present in some MDS entry (the pool is global, not per-AAGUID)
label          AAGUID resolved through the MDS -> "YubiKey 5 Series with NFC (Consumer
               Profile)", "Security Key Series with NFC (Consumer Profile)", "IDmelon", ...
hardware flag  never true for anything that is not a genuine vendor-issued device
```

`is_security_key: true` is easy: choose a currently-marketed AAGUID and a
certificate. `is_non_exportable_hardware_key: true` was never reached.

## What does not matter (each measured)

* Certificate content: subject, issuer, extension set, self-signed vs chained.
* Chain shape: self-made CA, fabricated two-level chain, the genuine Yubico B branch,
  the genuine Yubico A branch that a real fw 5.7.4+ key actually sends.
* Which vendor's anchors are appended: the pool is **global** — a Securitag AAGUID
  with a Yubico A-1 anchor in the chain is admitted.
* The `attStmt` signature: it is **not verified** (a statement signed by a key that
  does not match the leaf certificate is accepted).
* Attestation format: `packed` is admitted, `none` is admitted, `tpm` (both TPMT_SIGNATURE
  and DER encodings) is refused, `apple` is refused.
* Client-side claims: `clientExtensionResults.enterpriseAttestation` reaches the server
  verbatim and changes nothing.
* Certificate-vs-authData AAGUID: cross-checked. A mismatch is rejected.
* The MDS's published certificates: all 1102 end-entity anchors were tested — none is
  also a registered device key (0 have their SPKI hash in
  `attestationCertificateKeyIdentifiers`, 0 carry an AAGUID extension).

## What the flag therefore depends on

Corrected after the loop pointed out that the accepted Yubico entries carry **no**
`attestationCertificateKeyIdentifiers` at all (136 MDS entries have them; none of our
accepted AAGUIDs does; none is identifier-only).

So for the model we enrol with, the flag cannot be an identifier hash. It has to be
**path validation of the leaf certificate to an anchor in the MDS** — a signature the
leaf must carry from the vendor's CA. That fits every measurement:

* our leaf is genuinely issued by our own key, and appending the vendor's real anchors
  does not make the *path* valid (rows 4, 21, 27) — the anchors are present, the link
  is missing;
* the `attStmt` signature is a separate signature and is not checked (row 3), which is
  why forged statements enrol while the hardware flag stays false;
* identifiers exist for U2F-era and some legacy entries, but they are a second
  attribution path used *alongside* anchors, never instead of them.

Same wall, different mechanism: it is a vendor signature on the leaf, not a hash.

## The two ways to actually clear it

1. **A genuine MDS-listed key.** A YubiKey Security Key C NFC (~$29) is in the
   accepted set, is the only non-bundle model with a positive community report, and
   carries the registered leaf. This is the shortest path and it is a purchase, not a
   technique.
2. **Ask OpenAI.** They have changed the accepted set before, inside a week
   (TrustKey T110/T120: confirmed compatible 24 September, declared ineligible
   1 October). A support request that cites that timeline is a reasonable ask.

## Secondary finding worth reporting

Their enrolment accepts a packed attestation whose `attStmt.sig` is not the leaf
certificate's signature. Any relying party leaning on attestation should verify that
the statement was signed by the key in `x5c[0]`; this one does not. That belongs in a
disclosure to the affected party, not in a bypass.
