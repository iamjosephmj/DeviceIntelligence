#!/usr/bin/env python3
"""Fail if Google publishes a hardware-attestation root we do not pin.

This is the STALENESS check. Its sibling, check-pinned-roots.py, verifies that our
three mirrors agree with EACH OTHER — it cannot tell you the whole set has fallen
behind Google, because all three go stale together and stay perfectly consistent.

The failure that catches is nasty and quiet. If Google adds a root and we do not
pin it, devices whose attestation chains terminate there start failing
`chain -> pinned Google root`. Nothing errors: those are genuine, clean devices
being rejected, concentrated on newer hardware, while every other device and every
test stays green.

Needs network, so this is a SCHEDULED job, not a per-PR gate — a PR must never fail
because Google's endpoint had a bad afternoon.

The two directions are deliberately NOT symmetric:

  * Google has a root we DON'T pin  -> FAIL. Genuine devices are being rejected.
  * We pin a root Google no longer publishes -> WARN only. A retired root must stay
    pinned or every device provisioned under it stops verifying; attest_roots.h
    already says "keep both until Google retires one".

Usage:
  python3 tools/registry/check-google-roots.py [--url URL] [--timeout SECONDS]
"""

import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
PINNED = ROOT / "verifier/src/main/resources/pinned-roots.txt"
GOOGLE_ROOTS_URL = "https://android.googleapis.com/attestation/root"


def pinned_ders():
    """The base64-DER roots we ship, from the source of truth mirror."""
    if not PINNED.exists():
        sys.exit(f"pinned roots not found: {PINNED}")
    return [
        base64.b64decode(line.strip())
        for line in PINNED.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def google_ders(url, timeout):
    """Google publishes a JSON array of PEM strings. Tolerate a bare PEM bundle too."""
    with urllib.request.urlopen(url, timeout=timeout) as r:
        body = r.read().decode("utf-8")

    pems = None
    try:
        parsed = json.loads(body)
        if isinstance(parsed, list):
            pems = parsed
        elif isinstance(parsed, dict):  # some endpoints wrap it
            for v in parsed.values():
                if isinstance(v, list):
                    pems = v
                    break
    except json.JSONDecodeError:
        pass
    if pems is None:
        pems = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", body, re.S
        )
    if not pems:
        sys.exit(f"could not find any certificates in the response from {url}")

    out = []
    for pem in pems:
        b64 = "".join(
            re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)
        )
        out.append(base64.b64decode(re.sub(r"\s+", "", b64)))
    return out


def short(der):
    return hashlib.sha256(der).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=GOOGLE_ROOTS_URL)
    ap.add_argument("--timeout", type=int, default=30)
    a = ap.parse_args()

    ours = {short(d): d for d in pinned_ders()}
    try:
        theirs = {short(d): d for d in google_ders(a.url, a.timeout)}
    except Exception as e:  # network/DNS/TLS — do not fail the schedule on a blip
        print(f"could not reach {a.url}: {e}", file=sys.stderr)
        return 2

    missing = sorted(set(theirs) - set(ours))
    retired = sorted(set(ours) - set(theirs))

    for h in retired:
        print(f"note: we pin a root Google no longer publishes ({h}…). "
              f"KEEP IT — devices provisioned under it still attest to it.")

    if missing:
        print(f"\nGoogle publishes {len(missing)} attestation root(s) we do NOT pin:",
              file=sys.stderr)
        for h in missing:
            print(f"  sha256:{h}…  ({len(theirs[h])} bytes DER)", file=sys.stderr)
        print(
            "\nDevices attesting to these are being REJECTED as untrusted right now.\n"
            "Add them to all three mirrors, then re-run check-pinned-roots.py:\n"
            f"  1. {PINNED.relative_to(ROOT)}\n"
            "  2. tools/server/verify_token.py PINNED_ROOTS_B64\n"
            "  3. deviceintelligence/src/main/cpp/dicore/detectors/attestation/attest_roots.h",
            file=sys.stderr,
        )
        return 1

    print(f"pinned roots are current: {len(ours)} pinned, {len(theirs)} published by Google")
    return 0


if __name__ == "__main__":
    sys.exit(main())
