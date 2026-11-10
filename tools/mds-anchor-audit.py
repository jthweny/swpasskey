#!/usr/bin/env python3
"""Audit the FIDO MDS for entries whose trust anchor is not a CA.

The Metadata Statement spec allows a trust anchor to be "a root certificate, an
intermediate CA certificate or even the attestation certificate itself". For the
second and third cases the anchor is an end-entity certificate that is *public* in
the MDS — the only anchor class a software authenticator can legitimately hold.

    python3 tools/mds-anchor-audit.py --blob /tmp/mds.jwt
    python3 tools/mds-anchor-audit.py --blob /tmp/mds.jwt --dump /tmp/anchors

Outputs one line per interesting entry and, with --dump, writes each end-entity
anchor as DER so it can be fed to the bridge experiment env
(SWPASSKEY_BRIDGE_AAGUID / SWPASSKEY_BRIDGE_X5C).
"""
import argparse
import base64
import json
import pathlib
import sys

from cryptography import x509


def load_blob(path: pathlib.Path) -> dict:
    raw = path.read_text()
    payload = raw.split(".")[1] if raw.count(".") == 2 else raw
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def is_ca(der: bytes):
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--blob", default="/tmp/mds.jwt")
    ap.add_argument("--dump", default=None, help="directory for end-entity anchors (DER)")
    args = ap.parse_args()

    blob = load_blob(pathlib.Path(args.blob))
    print(f"MDS no={blob.get('no')} entries={len(blob['entries'])}", file=sys.stderr)
    out = pathlib.Path(args.dump) if args.dump else None
    if out:
        out.mkdir(parents=True, exist_ok=True)

    ee, empty = 0, 0
    for entry in blob["entries"]:
        st = entry.get("metadataStatement") or {}
        aaguid = entry.get("aaguid") or st.get("aaguid") or "(none)"
        roots = st.get("attestationRootCertificates") or []
        kp = ",".join(st.get("keyProtection") or []) or "-"
        at = ",".join(st.get("attestationTypes") or [])
        desc = st.get("description", "")

        if not roots:
            if "hardware" in kp or "secure_element" in kp:
                empty += 1
                print(f"NO-ANCHOR  {aaguid}  {desc[:44]:<44} kp={kp:<26} at={at}")
            continue

        kinds = [is_ca(base64.b64decode(r)) for r in roots]
        if any(k is False for k in kinds):
            ee += 1
            tag = "HARDWARE" if ("hardware" in kp or "secure_element" in kp) else "other"
            print(f"EE-ANCHOR  {aaguid}  {desc[:44]:<44} kp={kp:<26} at={at} ca={kinds} [{tag}]")
            if out is not None:
                for i, r in enumerate(roots):
                    if kinds[i] is False:
                        (out / f"anchor_{aaguid[:8]}.der").write_bytes(base64.b64decode(r))
    print(f"\nend-entity-anchored: {ee}   anchorless+hardware: {empty}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
