#!/usr/bin/env python3
"""Build a spec-shaped `tpm` attestation statement with no vendor material.

W3C WebAuthn §8.3 verifies a TPM statement by checking that `certInfo` has the
TPM_GENERATED magic and TPM_ST_ATTEST_CERTIFY type, that `extraData` is the hash of
authData‖clientDataHash, that `attested.name` is the TPM Name of `pubArea`, and that
`sig` is a valid TPMT_SIGNATURE over `certInfo` by the AIK certificate's key. None
of those steps anchors the AIK certificate to a vendor root — anchoring is a
separate, discretionary relying-party step, and for TPMs the certificate is normally
self-signed anyway.

So everything here is generated locally: an AIK key and a self-signed AIK cert
(empty Subject, TPM SAN, EKU tcg-kp-AIKCertificate, CA:FALSE) plus a pubArea that
matches the credential public key.
"""
from __future__ import annotations

import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.x509.oid import ObjectIdentifier

TPM_GENERATED = b"\xffTCG"
TPM_ST_ATTEST_CERTIFY = b"\x80\x17"
ALG_ECC = 0x0023
ALG_SHA256 = 0x000B
ALG_NULL = 0x0010
ALG_ECDSA = 0x0018
CURVE_NIST_P256 = 0x0003
OID_AIK_CERTIFICATE = ObjectIdentifier("2.23.133.8.3")
OID_TPM_MANUFACTURER = ObjectIdentifier("2.23.133.2.1")
OID_TPM_MODEL = ObjectIdentifier("2.23.133.2.2")
OID_TPM_VERSION = ObjectIdentifier("2.23.133.2.3")


def pub_area(x: bytes, y: bytes) -> bytes:
    out = struct.pack("!HHL", ALG_ECC, ALG_SHA256, 0x00040072)
    out += struct.pack("!H", 0)          # authPolicy: empty
    out += struct.pack("!H", ALG_NULL)   # symmetric
    out += struct.pack("!H", ALG_NULL)   # scheme
    out += struct.pack("!H", CURVE_NIST_P256)
    out += struct.pack("!H", ALG_NULL)   # kdf
    out += struct.pack("!H", len(x)) + x
    out += struct.pack("!H", len(y)) + y
    return out


def cert_info(auth_data: bytes, client_data_hash: bytes, area: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(area)
    name = struct.pack("!H", ALG_SHA256) + h.finalize()

    d = hashes.Hash(hashes.SHA256())
    d.update(auth_data + client_data_hash)
    extra = d.finalize()

    out = TPM_GENERATED + TPM_ST_ATTEST_CERTIFY
    out += struct.pack("!H", 0)                       # qualifiedSigner: empty
    out += struct.pack("!H", len(extra)) + extra      # extraData
    out += struct.pack("!QIIB", 1, 0, 0, 1)           # TPMS_CLOCK_INFO: clock, reset, restart, safe
    out += struct.pack("!Q", 0x00050000)              # firmwareVersion
    out += struct.pack("!H", len(name)) + name        # attested.name
    out += struct.pack("!H", 0)                       # attested.qualifiedName: empty
    return out


def aik_certificate(key, aaguid=None) -> bytes:
    name = x509.Name([])  # §8.3.1: Subject MUST be empty
    san = x509.SubjectAlternativeName([
        x509.DirectoryName(x509.Name([x509.NameAttribute(OID_TPM_MANUFACTURER, "id:FFFFF1D0")])),
        x509.DirectoryName(x509.Name([x509.NameAttribute(OID_TPM_MODEL, "swpasskey virtual TPM")])),
        x509.DirectoryName(x509.Name([x509.NameAttribute(OID_TPM_VERSION, "id:00050000")])),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(san, critical=False)
            .add_extension(x509.ExtendedKeyUsage([OID_AIK_CERTIFICATE]), critical=False))
    if aaguid:
        cert = cert.add_extension(
            x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
                                       b"\x04\x10" + bytes(aaguid)),
            critical=False)
    cert = cert.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def build(auth_data: bytes, client_data_hash: bytes, credential_xy, aaguid: bytes | None = None,
          sig_style: str = "tpm"):
    """Return (attStmt dict, fmt) for a TPM attestation of this authData."""
    x, y = credential_xy
    area = pub_area(x, y)
    info = cert_info(auth_data, client_data_hash, area)

    aik_key = ec.generate_private_key(ec.SECP256R1())
    der_sig = aik_key.sign(info, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    if sig_style == "der":
        sig = der_sig
    else:
        rb = r.to_bytes(32, "big")
        sb = s.to_bytes(32, "big")
        sig = struct.pack("!HH", ALG_ECDSA, ALG_SHA256)
        sig += struct.pack("!H", len(rb)) + rb
        sig += struct.pack("!H", len(sb)) + sb

    cert_der = aik_certificate(aik_key, aaguid)
    return {
        "ver": "2.0",
        "alg": -7,
        "sig": sig,
        "x5c": [cert_der],
        "certInfo": info,
        "pubArea": area,
    }, "tpm"
