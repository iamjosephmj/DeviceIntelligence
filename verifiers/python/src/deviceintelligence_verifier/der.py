"""Minimal DER TLV reader (Der.kt port) — high-tag numbers included."""
class Tlv:
    def __init__(self, tag: bytes, value: bytes):
        self.tag, self.value = tag, value


def read_tlv(b: bytes, i0: int):
    i = start = i0
    t = b[i] & 0xFF; i += 1
    if (t & 0x1F) == 0x1F:                      # high-tag-number form
        while (b[i] & 0x80) != 0:
            i += 1
        i += 1
    tag = b[start:i]
    n = b[i] & 0xFF; i += 1
    if n < 0x80:
        length = n
    else:
        k = n & 0x7F
        v = 0
        for _ in range(k):
            v = (v << 8) | (b[i] & 0xFF); i += 1
        length = v
    value = b[i:i + length]
    return Tlv(tag, value), i + length


def tlv_list(seq_value: bytes) -> list:
    out, i = [], 0
    while i < len(seq_value):
        tlv, i = read_tlv(seq_value, i)
        out.append(tlv)
    return out


def sequence_elements(der: bytes) -> list:
    tlv, _ = read_tlv(der, 0)
    return tlv_list(tlv.value)
