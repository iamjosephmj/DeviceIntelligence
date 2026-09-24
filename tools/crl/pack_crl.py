#!/usr/bin/env python3
"""Pack Google's attestation revocation list into the encrypted `crl.bin` asset
that libdicore reads at runtime (DICORE_CRL_KEY keystream, see attest_crl.cpp).

Fetches (or reads) https://android.googleapis.com/attestation/status, extracts the
revoked certificate serials, normalises them to minimal big-endian bytes, frames
them, and XOR-encrypts with a SHA-256 keystream keyed by the 32-byte build key.

Plaintext frame:  b"DCRL" | ver(1) | count(u32 LE) | [ len(u8) | serial_bytes ]...
Encrypted:        keystream_i = SHA256(key || u32_le(i));  cipher = plain XOR keystream

Usage:
  pack_crl.py --key <64-hex> [--in status.json | --url <url>] --out crl.bin
"""
import argparse
import hashlib
import json
import struct
import sys
import urllib.request

CRL_URL = "https://android.googleapis.com/attestation/status"
MAGIC = b"DCRL"
VERSION = 1


def normalise_serial(hex_serial: str) -> bytes:
    """Hex serial -> minimal big-endian bytes (no leading zero bytes), matching how
    libdicore normalises an mbedtls cert serial before comparing."""
    h = hex_serial.strip().lower().lstrip("0") or "0"
    if len(h) % 2:
        h = "0" + h
    b = bytes.fromhex(h)
    return b.lstrip(b"\x00") or b"\x00"


def keystream_xor(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    block = 0
    off = 0
    while off < len(data):
        ks = hashlib.sha256(key + struct.pack("<I", block)).digest()
        for i in range(len(ks)):
            if off + i >= len(data):
                break
            out[off + i] = data[off + i] ^ ks[i]
        off += len(ks)
        block += 1
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="32-byte build key as 64 hex chars")
    ap.add_argument("--in", dest="infile", help="local status.json (else fetch --url)")
    ap.add_argument("--url", default=CRL_URL)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    if len(key) != 32:
        print("key must be 32 bytes (64 hex)", file=sys.stderr)
        return 2

    if args.infile:
        with open(args.infile, "rb") as f:
            raw = f.read()
    else:
        with urllib.request.urlopen(args.url, timeout=60) as r:
            raw = r.read()
    entries = json.loads(raw).get("entries", {})

    serials = sorted({normalise_serial(s) for s in entries})
    frame = bytearray(MAGIC + bytes([VERSION]) + struct.pack("<I", len(serials)))
    for s in serials:
        if len(s) > 255:
            continue
        frame += bytes([len(s)]) + s

    cipher = keystream_xor(bytes(frame), key)
    with open(args.out, "wb") as f:
        f.write(cipher)
    print(f"packed {len(serials)} revoked serials -> {args.out} ({len(cipher)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
