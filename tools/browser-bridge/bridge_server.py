#!/usr/bin/env python3
"""Browser bridge: WebAuthn over HTTP for the page, CTAP2 over a socket for the daemon.

The page's `navigator.credentials` is replaced by bridge.js, which posts the
publicKey options here. This script builds clientDataJSON with the page's own
origin and challenge, drives a real CTAP2 ceremony against swpasskeyd's
development socket transport, and returns the attestation object the daemon
signed. A relying party therefore receives a genuine attestation - the profile's
AAGUID, the packed `x5c` certificate - without any USB device and without the
macOS HID entitlement.

    # daemon, socket transport, auto-approved presence
    SWPASSKEY_HID_SOCKET=/tmp/swpk.sock SWPASSKEY_TESTING=1 \\
      build/debug/swpasskeyd --testing --key-backend=software \\
      --store /tmp/swpk-bridge.bin --ctl-socket /tmp/swpk-bridge.sock &

    python3 tools/browser-bridge/bridge_server.py --hid-socket /tmp/swpk.sock

Then paste tools/browser-bridge/bridge.js into the target page's console.
Nothing leaves the machine; the page talks only to 127.0.0.1.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fido2 import cbor
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.pin import PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

HERE = Path(__file__).resolve().parent


# ----------------------------------------------------------------- CTAP plumbing
class SockConnection(CtapHidConnection):
    def __init__(self, path: str) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.sock.settimeout(30.0)

    def read_packet(self) -> bytes:
        buf = b""
        while len(buf) < 64:
            chunk = self.sock.recv(64 - len(buf))
            if not chunk:
                raise IOError("daemon closed the socket")
            buf += chunk
        return buf

    def write_packet(self, data: bytes) -> None:
        self.sock.sendall(data.ljust(64, b"\0"))

    def close(self) -> None:
        self.sock.close()


class Pin:
    """User verification over clientPIN protocol 2.

    The relying parties this is pointed at want `userVerification: "required"`,
    and so does the daemon: without a PIN it answers PIN_NOT_SET. Given a PIN, the
    bridge sets one on first use and then sends a pinUvAuthParam with every
    ceremony, exactly as a browser would.
    """

    def __init__(self, value: str) -> None:
        self.value = value
        self.protocol = PinProtocolV2()

    def parameter(self, ctap: Ctap2, permission, cdh: bytes, rp_id: str) -> bytes:
        client_pin = ClientPin(ctap, self.protocol)
        info = ctap.get_info()
        if not info.options.get("clientPin"):
            client_pin.set_pin(self.value)
            print("[bridge] PIN was not set; set it on the daemon", file=sys.stderr)
        token = client_pin.get_pin_token(
            self.value, permissions=permission, permissions_rpid=rp_id
        )
        return self.protocol.authenticate(token, cdh)


class CtapSession:
    """One connection per request: the CTAPHID channel is cheap to establish and
    a shared one would serialise every page tab behind the same CID."""

    def __init__(self, hid_socket: str, pin: "Pin | None") -> None:
        self.hid_socket = hid_socket
        self.pin = pin

    def __enter__(self) -> Ctap2:
        self.device = CtapHidDevice(
            HidDescriptor(self.hid_socket, 0x1209, 0xF1D0, 64, 64, "swpasskey", None),
            SockConnection(self.hid_socket),
        )
        return Ctap2(self.device)

    def __exit__(self, *exc) -> None:
        try:
            self.device.close()
        except Exception:
            pass


# ------------------------------------------------------------------- conversion
def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def client_data(kind: str, challenge: bytes, origin: str) -> bytes:
    # Chrome writes exactly this shape; a relying party parses type, challenge
    # and origin, and hashes the bytes.
    return json.dumps(
        {"type": kind, "challenge": b64u(challenge), "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode()


def parse_auth_data(auth_data: bytes) -> dict:
    out = {"flags": auth_data[32], "sign_count": int.from_bytes(auth_data[33:37], "big")}
    if auth_data[32] & 0x40 and len(auth_data) > 37:
        rest = auth_data[37:]
        out["aaguid"] = str(__import__("uuid").UUID(bytes=rest[:16]))
        id_len = int.from_bytes(rest[16:18], "big")
        out["credential_id"] = rest[18:18 + id_len]
        cose = cbor.decode(rest[18 + id_len:])
        out["cose"] = cose
    return out


# ----------------------------------------------------------------------- server
class Handler(BaseHTTPRequestHandler):
    server_version = "swpasskey-bridge/1.0"
    hid_socket = "/tmp/swpk.sock"
    pin: "Pin | None" = None
    verbose = False

    def log_message(self, fmt, *args):
        if self.verbose:
            sys.stderr.write("[bridge] " + fmt % args + "\n")

    # The page may live on any origin; the ceremony is what matters, and the
    # clientDataJSON carries the page's own origin for the relying party to check.
    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def do_OPTIONS(self):  # noqa: N802
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        if self.path in ("/bridge.js", "/"):
            self._send(200, (HERE / "bridge.js").read_bytes(), "text/javascript; charset=utf-8")
            return
        if self.path == "/health":
            self._json(200, {"ok": True, "hid_socket": self.hid_socket})
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            self._json(400, {"ok": False, "error": f"bad json: {exc}"})
            return
        try:
            if self.path == "/webauthn/create":
                self._json(200, self.make_credential(body))
            elif self.path == "/webauthn/get":
                self._json(200, self.get_assertion(body))
            else:
                self._json(404, {"ok": False, "error": "not found"})
        except Exception as exc:  # keep the page's console readable
            self._json(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def make_credential(self, body: dict) -> dict:
        challenge = b64u_decode(body["challenge"])
        origin = body["origin"]
        cdh = hashlib.sha256(client_data("webauthn.create", challenge, origin)).digest()
        rp = {"id": body["rpId"], "name": body.get("rpName") or body["rpId"]}
        user = {
            "id": b64u_decode(body["userId"]),
            "name": body.get("userName") or "user",
            "displayName": body.get("userDisplayName") or "",
        }
        options = {"rk": True}
        if body.get("userVerification") == "required":
            options["uv"] = True
        with CtapSession(self.hid_socket, Handler.pin) as ctap:
            pin_uv = None
            if options.get("uv") and Handler.pin is not None:
                pin_uv = Handler.pin.parameter(
                    ctap, ClientPin.PERMISSION.MAKE_CREDENTIAL, cdh, rp["id"]
                )
            attestation = ctap.make_credential(
                cdh, rp, user, [{"type": "public-key", "alg": -7}], options=options,
                pin_uv_param=pin_uv, pin_uv_protocol=2 if pin_uv else None,
            )
        auth_data = attestation.auth_data
        parsed = parse_auth_data(bytes(auth_data))
        att_obj = cbor.encode(
            {"fmt": attestation.fmt, "attStmt": attestation.att_stmt, "authData": bytes(auth_data)}
        )
        record = {
            "ok": True,
            "credentialId": b64u(parsed.get("credential_id", b"")),
            "clientDataJSON": b64u(client_data("webauthn.create", challenge, origin)),
            "attestationObject": b64u(att_obj),
            "fmt": attestation.fmt,
            "aaguid": parsed.get("aaguid"),
            "flags": parsed["flags"],
            "x5c": len(attestation.att_stmt.get("x5c") or []),
            "clientExtensionResults": {"credProps": {"rk": True}},
            "publicKeyAlgorithm": -7,
        }
        print(
            f"[bridge] create rp={rp['id']} fmt={record['fmt']} aaguid={record['aaguid']} "
            f"x5c={record['x5c']} flags=0x{record['flags']:02x}",
            file=sys.stderr,
        )
        return record

    def get_assertion(self, body: dict) -> dict:
        challenge = b64u_decode(body["challenge"])
        origin = body["origin"]
        cdh = hashlib.sha256(client_data("webauthn.get", challenge, origin)).digest()
        allow = [
            {"type": c.get("type", "public-key"), "id": b64u_decode(c["id"])}
            for c in body.get("allowCredentials") or []
        ]
        options = {"up": True}
        if body.get("userVerification") == "required":
            options["uv"] = True
        with CtapSession(self.hid_socket, Handler.pin) as ctap:
            pin_uv = None
            if options.get("uv") and Handler.pin is not None:
                pin_uv = Handler.pin.parameter(
                    ctap, ClientPin.PERMISSION.GET_ASSERTION, cdh, body["rpId"]
                )
            assertion = ctap.get_assertion(
                body["rpId"], cdh, allow_list=allow or None, options=options,
                pin_uv_param=pin_uv, pin_uv_protocol=2 if pin_uv else None,
            )
        parsed = parse_auth_data(bytes(assertion.auth_data))
        record = {
            "ok": True,
            "credentialId": b64u(parsed.get("credential_id", assertion.credential["id"])),
            "clientDataJSON": b64u(client_data("webauthn.get", challenge, origin)),
            "authenticatorData": b64u(bytes(assertion.auth_data)),
            "signature": b64u(assertion.signature),
            "userHandle": b64u(assertion.user["id"]) if assertion.user else None,
            "flags": parsed["flags"],
            "sign_count": parsed["sign_count"],
        }
        print(
            f"[bridge] get rp={body['rpId']} flags=0x{record['flags']:02x} "
            f"signCount={record['sign_count']}",
            file=sys.stderr,
        )
        return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--hid-socket", default=os.environ.get("SWPASSKEY_HID_SOCKET", "/tmp/swpk.sock"))
    parser.add_argument(
        "--pin",
        default=os.environ.get("SWPASSKEY_BRIDGE_PIN"),
        help="clientPIN used for user verification (default: $SWPASSKEY_BRIDGE_PIN). "
             "Set on the daemon on first use if it has none.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    Handler.hid_socket = args.hid_socket
    Handler.verbose = args.verbose
    Handler.pin = Pin(args.pin) if args.pin else None

    if not Path(args.hid_socket).exists():
        print(f"[bridge] warning: {args.hid_socket} does not exist yet; "
              f"start swpasskeyd with SWPASSKEY_HID_SOCKET first", file=sys.stderr)

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"[bridge] listening on http://{args.bind}:{args.port}/ "
          f"(CTAP socket {args.hid_socket})", file=sys.stderr)
    print(f"[bridge] inject with:  http://{args.bind}:{args.port}/bridge.js", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[bridge] bye", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
