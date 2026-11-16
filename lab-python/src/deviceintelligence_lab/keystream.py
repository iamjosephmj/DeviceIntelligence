"""The v1 wire-constant keystream, mint-side. Symmetric to the verifier's
decrypt: XOR with SHA256(key || u32le(block)) — encryption IS decryption."""
import hashlib

PHRASE = b"intel-verdict-token-key-v1"  # WIRE-CONSTANT (do NOT rebrand)


def encrypt_bytes(plain: bytes) -> bytes:
    key = hashlib.sha256(PHRASE).digest()
    out = bytearray(len(plain))
    off = block = 0
    while off < len(plain):
        ks = hashlib.sha256(key + block.to_bytes(4, "little")).digest()
        for i in range(min(32, len(plain) - off)):
            out[off + i] = plain[off + i] ^ ks[i]
        off += 32
        block += 1
    return bytes(out)


def encrypt_hex(plain: str) -> str:
    return encrypt_bytes(plain.encode("utf-8")).hex()
