#!/usr/bin/env bash
# gen-licence-key.sh — generate the X25519 keypair for hybrid-encrypt tokens (v2).
#
#   FRONTEND (device asset):   server.key            -> ship in the app (PUBLIC, safe)
#   BACKEND  (verifier secret): server-priv-<epoch>.pem -> the Kotlin :verifier decrypts
#                                                          with this; NEVER ship / commit.
#
# The device holds only the PUBLIC key, so there is no secret on the device to extract.
# The only secret is the backend private key — in production generate/hold it in an
# HSM/KMS, not a file. This script's file output is for the lab / dev loop.
#
# Usage:  bash tools/keys/gen-licence-key.sh [epoch 0..255] [outdir]
set -euo pipefail

EPOCH="${1:-0}"
OUTDIR="${2:-tools/keys/out}"
mkdir -p "$OUTDIR"
command -v openssl >/dev/null || { echo "FATAL: openssl not found"; exit 1; }
[ "$EPOCH" -ge 0 ] 2>/dev/null && [ "$EPOCH" -le 255 ] || { echo "FATAL: epoch must be 0..255"; exit 1; }

PRIV_PEM="$OUTDIR/server-priv-$EPOCH.pem"     # backend secret (PKCS#8; JDK loads directly)
LICENCE="$OUTDIR/server.key"                  # frontend asset (public)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# 1) X25519 private key (PKCS#8 PEM) — the backend's secret.
openssl genpkey -algorithm X25519 -out "$PRIV_PEM"
chmod 600 "$PRIV_PEM"

# 2) Extract the RAW 32-byte public key. For X25519 the SubjectPublicKeyInfo DER ends
#    with the raw key, so `tail -c 32` yields the 32 raw bytes.
openssl pkey -in "$PRIV_PEM" -pubout -outform DER | tail -c 32 > "$TMP/pub.raw"
[ "$(wc -c < "$TMP/pub.raw")" -eq 32 ] || { echo "FATAL: pubkey extract != 32 bytes"; exit 1; }

# 3) Assemble server.key:
#    magic(4)="RVN1" ver(1)=0x01 epoch(1) curve(1)=0x01(X25519) rsvd(1)=0x00 pubkey(32) checksum(32)
{
  printf 'RVN1'
  printf '\x01'
  printf "$(printf '\\x%02x' "$EPOCH")"
  printf '\x01'
  printf '\x00'
  cat "$TMP/pub.raw"
} > "$TMP/body"                                 # 40 bytes
[ "$(wc -c < "$TMP/body")" -eq 40 ] || { echo "FATAL: body != 40 bytes"; exit 1; }
# checksum = SHA256(body) as 32 raw bytes
sha256sum "$TMP/body" | cut -d' ' -f1 | xxd -r -p > "$TMP/sum"
cat "$TMP/body" "$TMP/sum" > "$LICENCE"           # 72 bytes total

# 4) Report
PUBHEX="$(xxd -p -c 64 "$TMP/pub.raw")"
echo "OK  epoch=$EPOCH"
echo "  frontend : $LICENCE            ($(wc -c < "$LICENCE") bytes, PUBLIC — ship as the app asset)"
echo "  backend  : $PRIV_PEM  (SECRET — load in :verifier, never ship/commit)"
echo "  pubkey   : $PUBHEX"
echo
echo "  Next: copy server.key to the app assets, and point the verifier at $PRIV_PEM"
echo "        (epoch $EPOCH). Rotate by re-running with a higher epoch; keep old .pem for the grace window."
