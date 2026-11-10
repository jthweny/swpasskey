#!/usr/bin/env python3
"""Print the subject CN of every DeveloperCertificates entry in a .provisionprofile.

Used by run.sh to sign with the certificate the profile actually authorises: a
profile listing a Developer ID cert is not satisfied by an Apple Development one,
and the mismatch shows up as an unspecific signing or launch failure.
"""
import plistlib
import subprocess
import sys
import tempfile


def cn_of(der: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".der") as fh:
        fh.write(der)
        fh.flush()
        out = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-in", fh.name],
            capture_output=True, text=True, timeout=10)
    line = out.stdout.strip()
    if not line:
        return ""
    # "subject= /OU=.../CN=Apple Development: Name (TEAM)"
    for part in line.split("/"):
        if part.startswith("CN="):
            return part[3:].strip()
    return line


def main() -> int:
    with open(sys.argv[1], "rb") as fh:
        profile = plistlib.load(fh)
    for cert in profile.get("DeveloperCertificates", []):
        print(cn_of(cert))
    return 0


if __name__ == "__main__":
    sys.exit(main())
