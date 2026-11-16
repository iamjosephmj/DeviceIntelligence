#!/usr/bin/env python3
"""Fail if the pinned Google attestation-root mirrors diverge.

The same trust anchors are duplicated in three places:

  1. verifier/src/main/resources/pinned-roots.txt          (:verifier, base64 DER)
  2. tools/server/verify_token.py PINNED_ROOTS_B64         (python backend, base64)
  3. .../attestation/attest_roots.h kGoogleAttestRoot*      (native, decimal bytes)

A genuine device fails `chain -> pinned Google root` on whichever service holds
the stale list, so drift here is a silent outage rather than a loud error — and
the native copy is the one that ships to devices. There is a CI check for signal
registry drift; this is its counterpart for the roots.

Compares the SHA-256 of the sorted set of DER bodies, so ordering and encoding
differences between the three do not register as drift.
"""

import base64
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def digest(ders):
    return hashlib.sha256(b"".join(sorted(ders))).hexdigest()


def from_txt(path):
    """Base64 DER, one per line, '#' comments."""
    return [
        base64.b64decode(line.strip())
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def from_py(path):
    """PINNED_ROOTS_B64 = [ "...", "..." ] in verify_token.py."""
    m = re.search(r"PINNED_ROOTS_B64\s*=\s*\[(.*?)\]", path.read_text(), re.S)
    if not m:
        sys.exit(f"PINNED_ROOTS_B64 not found in {path}")
    blobs = re.findall(r"[\"']([A-Za-z0-9+/=\s]{40,})[\"']", m.group(1))
    return [base64.b64decode(re.sub(r"\s+", "", b)) for b in blobs]


def from_cpp(path):
    """static const unsigned char kGoogleAttestRootN[]={48,130,...};"""
    text = path.read_text()
    out = []
    for body in re.findall(
        r"kGoogleAttestRoot\d+\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;", text, re.S
    ):
        out.append(bytes(int(b) for b in re.findall(r"\d+", body)))
    if not out:
        sys.exit(f"kGoogleAttestRoot* arrays not found in {path}")
    return out


SOURCES = {
    "verifier resource": (
        from_txt,
        ROOT / "verifier/src/main/resources/pinned-roots.txt",
    ),
    "verify_token.py": (
        from_py,
        ROOT / "tools/server/verify_token.py",
    ),
    "native attest_roots.h": (
        from_cpp,
        ROOT / "deviceintelligence/src/main/cpp/dicore/detectors/attestation/attest_roots.h",
    ),
}


def main():
    loaded = {}
    for name, (fn, path) in SOURCES.items():
        if not path.exists():
            sys.exit(f"missing pinned-root source: {path}")
        loaded[name] = fn(path)

    digests = {name: digest(ders) for name, ders in loaded.items()}
    if len(set(digests.values())) != 1:
        print("pinned-root mirrors have DRIFTED:", file=sys.stderr)
        for name, d in digests.items():
            print(f"  {name:24} {d}  ({len(loaded[name])} roots)", file=sys.stderr)
        print(
            "\nA device whose chain reaches a root missing from one mirror fails\n"
            "verification against that service only. Fix the lagging copy.",
            file=sys.stderr,
        )
        return 1

    n = len(next(iter(loaded.values())))
    print(f"pinned roots in sync across {len(loaded)} mirrors: "
          f"{next(iter(digests.values()))[:16]}… ({n} roots)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
