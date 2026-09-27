"""Minimal DER writer — the exact inverse of the verifier's text.der reader,
covering the tag forms the KeyDescription uses (incl. the high-tag-number
[704] RootOfTrust entry)."""
def tlv(tag: bytes | int, value: bytes) -> bytes:
    tag = bytes([tag]) if isinstance(tag, int) else tag
    n = len(value)
    if n < 0x80:
        return tag + bytes([n]) + value
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return tag + bytes([0x80 | len(length_bytes)]) + length_bytes + value


def sequence(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(n: int) -> bytes:
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return tlv(0x02, body)


def enumerated(n: int) -> bytes:
    return tlv(0x0A, bytes([n & 0xFF]))


def octet_string(b: bytes) -> bytes:
    return tlv(0x04, b)


def boolean(flag: bool) -> bytes:
    return tlv(0x01, b"\xff" if flag else b"\x00")
