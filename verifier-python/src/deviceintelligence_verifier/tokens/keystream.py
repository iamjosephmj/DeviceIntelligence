"""v1 symmetric token crypto (Keystream.kt). Confidentiality in transit only."""
import hashlib

PHRASE = b"intel-verdict-token-key-v1"  # WIRE-CONSTANT (do NOT rebrand)


def decrypt_bytes(cipher: bytes) -> bytes:
    key = hashlib.sha256(PHRASE).digest()
    out = bytearray(len(cipher))
    off = block = 0
    while off < len(cipher):
        blk = block.to_bytes(4, "little")
        ks = hashlib.sha256(key + blk).digest()
        for i in range(min(32, len(cipher) - off)):
            out[off + i] = cipher[off + i] ^ ks[i]
        off += 32
        block += 1
    return bytes(out)


def decrypt_hex(token_hex: str) -> str:
    return decrypt_bytes(bytes.fromhex(token_hex.strip())).decode("utf-8")
