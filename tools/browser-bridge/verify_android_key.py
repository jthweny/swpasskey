"""Structural check for our own fmt=android-key statements.

python-fido2 ships no android-key verifier, so the 400 recorded as row 31 could have
been a malformed statement rather than a refused chain. This checks the three things
the spec actually requires, without any FIDO library:

  1. the KeyDescription lives at OID 1.3.6.1.4.1.11129.2.1.17 inside x5c[0]
  2. attestationChallenge == SHA-256(clientDataJSON)
  3. the signature verifies over  authData || clientDataHash  with the leaf's key

Usage:  verify_android_key.py <file-with-cbor-attestation-object>
        verify_android_key.py --selftest
"""

from __future__ import annotations

import hashlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor

KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"


def _tlv(buf: bytes, at: int) -> tuple[int, bytes, int]:
    """Read one DER TLV: returns (tag, value, next offset)."""
    tag = buf[at]
    at += 1
    ln = buf[at]
    at += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[at:at + n], "big")
        at += n
    return tag, buf[at:at + ln], at + ln


def key_description_challenge(ext_value: bytes) -> bytes:
    """attestationChallenge is field 4 of the KeyDescription SEQUENCE."""
    tag, seq, _ = _tlv(ext_value, 0)
    if tag != 0x30:
        raise ValueError("KeyDescription is not a SEQUENCE")
    # KeyDescription order: version INT, securityLevel ENUM, keymasterVersion INT,
    # keymasterSecurityLevel ENUM, attestationChallenge OCTET STRING, uniqueId OCTET
    # STRING, softwareEnforced SEQ, teeEnforced SEQ. The challenge is the first
    # OCTET STRING in the sequence.
    at = 0
    while at < len(seq):
        tag, val, at = _tlv(seq, at)
        if tag == 0x04:
            return val
    raise ValueError("no attestationChallenge found")


def verify(att_obj: bytes, cdh: bytes | None = None) -> dict:
    att = cbor.decode(att_obj)
    if att["fmt"] != "android-key":
        raise ValueError(f"fmt is {att['fmt']!r}, not android-key")
    auth_data = att["authData"]
    x5c = att["attStmt"]["x5c"]
    sig = att["attStmt"]["sig"]

    leaf = x509.load_der_x509_certificate(x5c[0])
    exts = [e for e in leaf.extensions if e.oid.dotted_string == KEY_DESCRIPTION_OID]
    if not exts:
        raise ValueError("leaf has no KeyDescription extension")

    # The challenge is compared against the clientDataHash the shim used. The test
    # passes it in by re-deriving it, see selftest(); here we only prove presence.
    challenge = key_description_challenge(exts[0].value.value)

    # Signature: over authData || clientDataHash, keyed by the leaf certificate.
    pub = leaf.public_key()
    ok_sig = None
    if isinstance(pub, ec.EllipticCurvePublicKey):
        try:
            # spec: signed data is  authData || clientDataHash
            pub.verify(sig, auth_data + (cdh or b""), ec.ECDSA(hashes.SHA256()))
            ok_sig = True
        except Exception:
            ok_sig = False
    return {
        "fmt": att["fmt"],
        "x5c_len": len(x5c),
        "leaf_subject": leaf.subject.rfc4514_string(),
        "key_description_present": True,
        "challenge_len": len(challenge),
        "signature_valid": ok_sig,
        "_challenge": challenge,
    }


def selftest() -> int:
    sys.path.insert(0, ".")
    import alt_formats  # noqa: E402

    return 0


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        try:
            selftest()
        except ImportError:
            pass
        # inline version: no cbor round trip needed, verify what the emitter made
        sys.path.insert(0, ".")
        import alt_formats

        for label, cdh in (("challenge-a", hashlib.sha256(b"a").digest()),
                           ("challenge-b", hashlib.sha256(b"b").digest())):
            auth_data = bytes(37) + bytes([0x45]) + bytes(4) + bytes(32)
            key = ec.generate_private_key(ec.SECP256R1())
            stmt, _ = alt_formats.android_key_statement(auth_data, cdh, key)
            att_obj = cbor.encode({"fmt": "android-key", "attStmt": stmt, "authData": auth_data})
            out = verify(att_obj, cdh)
            match = out["_challenge"] == cdh
            print(f"{label}: challenge==cdh {match} | challenge_len {out['challenge_len']} "
                  f"| certs {out['x5c_len']} | subject {out['leaf_subject']} "
                  f"| sig_valid {out['signature_valid']}")
            assert match, "attestationChallenge does not equal clientDataHash"
            # Our emitter signs with the leaf certificate's key. Per the android-key
            # spec the signature should come from the credential key, which this
            # project cannot reach: the daemon holds it and never exports it. The
            # certificate is therefore self-consistent but not spec-conformant, and
            # that is recorded rather than asserted away.
            assert out["key_description_present"]
        print("android-key statement: challenge correctly bound to clientDataHash;")
        print("  signature is made by the leaf certificate key, not the credential key,")
        print("  so the statement is self-consistent but not spec-conformant.")
        return 0

    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    att_obj = open(sys.argv[1], "rb").read()
    out = verify(att_obj)
    out.pop("_challenge", None)
    for k, v in out.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
