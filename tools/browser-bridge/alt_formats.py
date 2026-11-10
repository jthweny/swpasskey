#!/usr/bin/env python3
"""Emitters for the attestation formats the fork never produced: fido-u2f and
android-key.

`fido-u2f` is the interesting one: its statement is signed by the *credential* key
over `0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F`, so a
software authenticator can produce a statement whose signature is genuinely valid
under its (unregistered) attestation certificate — no separate attestation key and
no vendor material.

`android-key` needs a KeyDescription ASN.1 extension carrying the challenge; the
chain is expected to reach a Google root, which ours does not.
"""
from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

ANDROID_KEY_ATTESTATION_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def u2f_statement(auth_data: bytes, client_data_hash: bytes, leaf_der: bytes, leaf_key, xy=None):
    """attStmt for fmt=fido-u2f: {sig, x5c}.

    The U2F message is 0x00 || rpIdHash || clientDataHash || credentialId ||
    0x04||x||y. The coordinates are passed in because authData carries the COSE key
    followed by an extension map, which a single decode cannot consume.
    """
    rp_id_hash = auth_data[0:32]
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_id_len]
    if xy is None:
        raise ValueError("u2f_statement needs the credential key coordinates")
    x, y = xy
    pub = b"\x04" + bytes(x) + bytes(y)
    msg = b"\x00" + rp_id_hash + client_data_hash + cred_id + pub
    sig = leaf_key.sign(msg, ec.ECDSA(hashes.SHA256()))
    stmt = {"sig": sig, "x5c": [leaf_der]}
    return stmt, "fido-u2f"


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def android_key_statement(auth_data: bytes, client_data_hash: bytes, leaf_key, subject_cn="android-key"):
    """attStmt for fmt=android-key: {alg, sig, x5c} with a KeyDescription extension."""
    # KeyDescription ::= SEQUENCE { attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
    #   keymasterVersion INTEGER, keymasterSecurityLevel ENUMERATED,
    #   attestationChallenge OCTET_STRING, uniqueId OCTET_STRING,
    #   softwareEnforced AuthorizationList, teeEnforced AuthorizationList }
    # Minimal, structurally valid: two empty SEQUENCEs for the authorization lists.
    challenge = _tlv(0x04, client_data_hash)
    body = (_tlv(0x02, b"\x03") + _tlv(0x0A, b"\x00") + _tlv(0x02, b"\x04") +
            _tlv(0x0A, b"\x01") + challenge + _tlv(0x04, b"") + _tlv(0x30, b"") + _tlv(0x30, b""))
    key_desc = _tlv(0x30, body)

    now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
               .public_key(leaf_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now)
               .not_valid_after(now + __import__("datetime").timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.UnrecognizedExtension(ANDROID_KEY_ATTESTATION_OID, key_desc),
                              critical=False))
    cert = builder.sign(leaf_key, hashes.SHA256())
    der = cert.public_bytes(serialization.Encoding.DER)
    sig = leaf_key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
    return {"alg": -7, "sig": sig, "x5c": [der]}, "android-key"
