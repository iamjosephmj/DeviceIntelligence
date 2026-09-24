#!/usr/bin/env python3
"""Generate a DEVELOPMENT RVN2 licence blob + its private key.

  python3 tools/keys/gen-dev-licence.py <applicationId> <out-dir> [--epoch N] [--not-after EPOCH_SECONDS]

THIS IS FOR TESTS AND THE SAMPLE ONLY. The publisher key it signs with is the one
compiled into dicore/crypto/licence_blob.cpp, which ships inside the APK and is therefore
public by assumption — the blob check is a fail-fast, not a security control (see
docs/superpowers/specs/2026-08-25-scan-api-design.md). Release builds must mint their
key material with the the `deviceintelligenceGenerateKey` Gradle task and a publisher key held in the
release pipeline, NOT with this script.

Produces, byte-identical to LicenceKeygen.generate():

  server.key            144 bytes, the PUBLIC asset shipped in the APK
  server-priv-<epoch>.pem the X25519 private half, loaded by the backend

  magic(4)="RVN2" ver(1)=2 epoch(1) curve(1)=1 flags(1)
  pubkey(32) pkgHash(32) notAfter(8, big-endian) sig(64)
  sig[0:32] = HMAC-SHA256(publisherKey, blob[0:80]); sig[32:64] = 0 (reserved)
"""

import argparse
import hashlib
import hmac
import pathlib
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
LICENCE_CPP = ROOT / "deviceintelligence/src/main/cpp/dicore/crypto/licence_blob.cpp"


def publisher_key():
    """Read kPublisherKey straight out of the native source, so the two cannot drift."""
    m = re.search(
        r"kPublisherKey\s*\[\s*32\s*\]\s*=\s*\{(.*?)\}\s*;", LICENCE_CPP.read_text(), re.S
    )
    if not m:
        sys.exit(f"kPublisherKey not found in {LICENCE_CPP}")
    key = bytes(int(b, 16) for b in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))
    if len(key) != 32:
        sys.exit(f"kPublisherKey is {len(key)} bytes, expected 32")
    return key


def build(app_id, epoch, not_after, priv):
    raw_pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert len(raw_pub) == 32

    body = bytearray(80)
    body[0:4] = b"RVN2"
    body[4] = 0x02
    body[5] = epoch
    body[6] = 0x01  # X25519
    body[7] = 0x00  # flags
    body[8:40] = raw_pub
    body[40:72] = hashlib.sha256(app_id.encode("utf-8")).digest()
    body[72:80] = not_after.to_bytes(8, "big")

    tag = hmac.new(publisher_key(), bytes(body), hashlib.sha256).digest()
    return bytes(body) + tag + bytes(32), raw_pub


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("application_id")
    ap.add_argument("out_dir")
    ap.add_argument("--epoch", type=int, default=0)
    ap.add_argument("--not-after", type=int, default=0, help="epoch seconds; 0 = never")
    a = ap.parse_args()

    if not 0 <= a.epoch <= 255:
        sys.exit("epoch must be 0..255")

    out = pathlib.Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    priv = X25519PrivateKey.generate()
    blob, raw_pub = build(a.application_id, a.epoch, a.not_after, priv)
    assert len(blob) == 144

    (out / "server.key").write_bytes(blob)
    pem = out / f"server-priv-{a.epoch}.pem"
    pem.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pem.chmod(0o600)

    print(f"app      : {a.application_id}")
    print(f"epoch    : {a.epoch}   notAfter: {a.not_after or 'never'}")
    print(f"asset    : {out / 'server.key'}  (PUBLIC — ships in the APK)")
    print(f"private  : {pem}  (backend half)")
    print(f"pubkey   : {raw_pub.hex()}")


if __name__ == "__main__":
    main()
