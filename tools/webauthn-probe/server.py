#!/usr/bin/env python3
"""WebAuthn probe for the swpasskey compat fork.

Serves a page that asks for exactly what OpenAI Daybreak asks for — a
cross-platform, discoverable, user-verified credential with
`attestation: "direct"` — then decodes what the authenticator actually sent
(fmt, x5c, AAGUID, BE/BS, UV, signCount) and appends it to
`registrations.jsonl` so a backend verdict can be tied to specific bytes.

    python3 tools/webauthn-probe/server.py                # http://localhost:8080
    python3 tools/webauthn-probe/server.py --port 9000
    python3 tools/webauthn-probe/server.py --tls          # self-signed HTTPS

`http://localhost` is a secure context in Chrome, so TLS is optional. With
`--tls` the certificate is generated into ./certs (openssl, git-ignored).

Nothing here talks to OpenAI; it records the registration this machine produced
so the reply from the target service can be compared against it.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASSETS = HERE
LOG = HERE / "registrations.jsonl"

RP_ID = "localhost"
RP_NAME = "Daybreak Attestation Probe"
USER_NAME = "probe@localhost"
USER_DISPLAY = "Probe User"
USER_HANDLE = b"probe-user-handle-0001"

FLAG_NAMES = [
    (0x01, "UP"),
    (0x02, "RFU1"),
    (0x04, "UV"),
    (0x08, "BE"),
    (0x10, "BS"),
    (0x40, "AT"),
    (0x80, "ED"),
]


# --------------------------------------------------------------------------- CBOR
class CborError(ValueError):
    pass


def cbor_decode(data: bytes, offset: int = 0):
    """Definite-length CBOR only: that is all CTAP2 emits."""
    if offset >= len(data):
        raise CborError("truncated")
    initial = data[offset]
    offset += 1
    major, info = initial >> 5, initial & 0x1F
    if info < 24:
        value = info
    elif info == 24:
        value = data[offset]
        offset += 1
    elif info == 25:
        value = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
    elif info == 26:
        value = int.from_bytes(data[offset:offset + 4], "big")
        offset += 4
    elif info == 27:
        value = int.from_bytes(data[offset:offset + 8], "big")
        offset += 8
    else:
        raise CborError("indefinite or reserved length")

    if major == 0:
        return value, offset
    if major == 1:
        return -1 - value, offset
    if major == 2:
        return data[offset:offset + value], offset + value
    if major == 3:
        return data[offset:offset + value].decode("utf-8", "replace"), offset + value
    if major == 4:
        out = []
        for _ in range(value):
            item, offset = cbor_decode(data, offset)
            out.append(item)
        return out, offset
    if major == 5:
        out = {}
        for _ in range(value):
            key, offset = cbor_decode(data, offset)
            val, offset = cbor_decode(data, offset)
            out[key] = val
        return out, offset
    if major == 7:
        if info == 20:
            return False, offset
        if info == 21:
            return True, offset
        if info == 22:
            return None, offset
        return ("simple", info), offset
    raise CborError(f"unsupported major type {major}")


# ----------------------------------------------------------------------- helpers
def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# id-fido-gen-ce-aaguid 1.3.6.1.4.1.45724.1.1.4, DER encoded
AAGUID_EXT_OID = bytes.fromhex("060b2b0601040182e51c010104")


def aaguid_extension(der: bytes) -> str | None:
    """Pure-Python AAGUID extension lookup: LibreSSL's `x509` has no -ext."""
    at = der.find(AAGUID_EXT_OID)
    if at < 0:
        return None
    # ... followed by critical flag, then OCTET STRING( OCTET STRING(16 bytes) ).
    tail = der[at + len(AAGUID_EXT_OID):]
    marker = bytes.fromhex("04120410")
    pos = tail.find(marker)
    if pos < 0 or len(tail) < pos + len(marker) + 16:
        return None
    return str(__import__("uuid").UUID(bytes=tail[pos + len(marker):pos + len(marker) + 16]))


def cert_summary(der: bytes) -> dict:
    """Subject/issuer/fingerprint from the openssl CLI, AAGUID extension in
    pure Python (macOS ships LibreSSL, whose `x509 -ext` support is missing)."""
    info = {"der_len": len(der)}
    ext = aaguid_extension(der)
    if ext is not None:
        info["aaguid_ext"] = ext
    try:
        out = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer",
             "-fingerprint", "-sha256"],
            input=der, capture_output=True, timeout=10, check=True,
        ).stdout.decode("utf-8", "replace")
    except (subprocess.SubprocessError, OSError):
        info["note"] = "openssl unavailable; subject/issuer not decoded"
        return info
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            info["subject"] = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[len("issuer="):].strip()
        elif line.lower().startswith("sha256 fingerprint="):
            info["sha256"] = line.split("=", 1)[1].strip().replace(":", "").lower()
    info["self_signed"] = info.get("subject") == info.get("issuer")
    return info


def decode_auth_data(auth_data: bytes) -> dict:
    if len(auth_data) < 37:
        raise ValueError("authData shorter than 37 bytes")
    out = {
        "rp_id_hash": auth_data[:32].hex(),
        "flags_byte": auth_data[32],
        "flags": [name for bit, name in FLAG_NAMES if auth_data[32] & bit],
        "sign_count": int.from_bytes(auth_data[33:37], "big"),
    }
    if auth_data[32] & 0x40:
        rest = auth_data[37:]
        if len(rest) < 18:
            raise ValueError("attested credential data truncated")
        out["aaguid"] = str(__import__("uuid").UUID(bytes=rest[:16]))
        id_len = int.from_bytes(rest[16:18], "big")
        out["credential_id"] = rest[18:18 + id_len].hex()
        cose, _ = cbor_decode(rest[18 + id_len:])
        out["credential_public_key"] = {
            "kty": cose.get(1), "alg": cose.get(3), "crv": cose.get(-1),
            "x": b64u(cose.get(-2, b"")), "y": b64u(cose.get(-3, b"")),
        }
    return out


def decode_registration(body: dict) -> dict:
    response = body.get("response", {})
    att_bytes = b64u_decode(response.get("attestationObject", ""))
    client_data_json = b64u_decode(response.get("clientDataJSON", ""))
    att_obj = cbor_decode(att_bytes)[0]
    auth_data = att_obj["authData"]
    stmt = att_obj.get("attStmt") or {}
    chain = stmt.get("x5c") or []
    client = json.loads(client_data_json)
    record = {
        "received": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "fmt": att_obj.get("fmt"),
        "attestation_object_len": len(att_bytes),
        "auth_data": decode_auth_data(auth_data),
        "client_data": {
            "type": client.get("type"),
            "challenge": client.get("challenge"),
            "origin": client.get("origin"),
            "crossOrigin": client.get("crossOrigin", False),
        },
        "att_stmt_keys": sorted(stmt.keys()),
        "x5c_present": bool(chain),
        "x5c_len": len(chain),
        "x5c": [cert_summary(c) for c in chain],
        "user_handle": b64u_decode(response["userHandle"]).hex() if response.get("userHandle") else None,
        "raw_id": body.get("rawId"),
        "transports": (body.get("response", {}).get("getTransports") or []),
    }
    if not chain:
        record["attestation_kind"] = "self (credential key, no chain)"
    elif record["x5c"] and record["x5c"][0].get("self_signed"):
        record["attestation_kind"] = "x5c present, self-signed leaf"
    else:
        record["attestation_kind"] = "x5c present, vendor-style chain"
    return record


# ------------------------------------------------------------------------ server
class Handler(BaseHTTPRequestHandler):
    server_version = "swpasskey-probe/1.0"
    challenges: dict = {}

    def log_message(self, fmt, *args):  # keep the console readable
        sys.stderr.write("[probe] " + fmt % args + "\n")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, indent=2).encode(), "application/json")

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            return self._send(200, (ASSETS / "index.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/options/register":
            challenge = secrets.token_bytes(32)
            self.challenges[b64u(challenge)] = "register"
            return self._json(200, {
                "publicKey": {
                    "rp": {"id": RP_ID, "name": RP_NAME},
                    "user": {"id": b64u(USER_HANDLE), "name": USER_NAME,
                             "displayName": USER_DISPLAY},
                    "challenge": b64u(challenge),
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7},
                                         {"type": "public-key", "alg": -257}],
                    "timeout": 90000,
                    "excludeCredentials": [],
                    "authenticatorSelection": {
                        "authenticatorAttachment": "cross-platform",
                        "residentKey": "required",
                        "requireResidentKey": True,
                        "userVerification": "required",
                    },
                    "attestation": "direct",
                    "extensions": {"credProps": True},
                }
            })
        if path == "/options/login":
            challenge = secrets.token_bytes(32)
            self.challenges[b64u(challenge)] = "login"
            return self._json(200, {
                "publicKey": {
                    "challenge": b64u(challenge),
                    "rpId": RP_ID,
                    "timeout": 90000,
                    "userVerification": "required",
                    "allowCredentials": [],  # discoverable flow
                }
            })
        if path == "/log":
            if LOG.exists():
                return self._send(200, LOG.read_bytes(), "application/x-ndjson")
            return self._send(200, b"", "application/x-ndjson")
        return self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            return self._json(400, {"error": f"bad json: {exc}"})
        path = self.path.split("?", 1)[0]

        if path == "/register":
            try:
                record = decode_registration(body)
            except (CborError, KeyError, ValueError) as exc:
                return self._json(400, {"error": f"cannot decode: {exc}"})
            challenge = record["client_data"]["challenge"]
            if self.challenges.pop(challenge, None) != "register":
                return self._json(400, {"error": "unknown or replayed challenge"})
            with LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            return self._json(200, {"ok": True, "record": record})

        if path == "/login":
            response = body.get("response", {})
            try:
                client = json.loads(b64u_decode(response.get("clientDataJSON", "")))
                auth_data = b64u_decode(response.get("authenticatorData", ""))
            except (ValueError, json.JSONDecodeError) as exc:
                return self._json(400, {"error": f"cannot decode: {exc}"})
            if self.challenges.pop(client.get("challenge", ""), None) != "login":
                return self._json(400, {"error": "unknown or replayed challenge"})
            record = {
                "received": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "kind": "assertion",
                "auth_data": decode_auth_data(auth_data),
                "user_handle": b64u_decode(response.get("userHandle") or "").hex()
                               if response.get("userHandle") else None,
                "signature_len": len(b64u_decode(response.get("signature", ""))),
            }
            with LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            return self._json(200, {"ok": True, "record": record})

        return self._json(404, {"error": "not found"})


def ensure_tls_cert(directory: Path) -> tuple[Path, Path]:
    directory.mkdir(exist_ok=True)
    cert, key = directory / "localhost.pem", directory / "localhost.key"
    if not (cert.exists() and key.exists()):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-days", "7", "-keyout", str(key), "-out", str(cert),
             "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True,
        )
        key.chmod(0o600)
        print(f"[probe] wrote {cert} (7-day self-signed cert)", file=sys.stderr)
    return cert, key


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    scheme = "http"
    if args.tls:
        cert, key = ensure_tls_cert(HERE / "certs")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"[probe] {scheme}://{args.bind}:{args.port}/  (records → {LOG})", file=sys.stderr)
    print(f"[probe] rpId={RP_ID} attestation=direct "
          f"attachment=cross-platform rk=required uv=required", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[probe] bye", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
