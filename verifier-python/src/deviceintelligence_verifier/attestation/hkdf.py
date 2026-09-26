"""HKDF-SHA256 (RFC 5869), Extract-then-Expand. Empty salt -> 32 zero bytes."""
import hashlib, hmac

def sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int) -> bytes:
    if not 0 <= out_len <= 255 * 32:
        raise ValueError(f"HKDF outLen out of range: {out_len}")
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, pos, counter = b"", b"", 0, 1
    while pos < out_len:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        take = min(len(t), out_len - pos)
        out += t[:take]
        pos += take
        counter += 1
    return out
