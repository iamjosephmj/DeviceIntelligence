"""RFC 5869 known-answer tests — via the hkdf module."""
import pytest
from deviceintelligence_verifier import hkdf

IKM22 = bytes.fromhex("0b" * 22)


def test_rfc5869_case1_with_salt_and_info():
    okm = hkdf.sha256(IKM22, bytes.fromhex("000102030405060708090a0b0c"),
                      bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"


def test_rfc5869_case3_empty_salt_and_info():
    okm = hkdf.sha256(IKM22, b"", b"", 42)
    assert okm.hex() == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"


def test_rejects_output_over_255_blocks():
    with pytest.raises(ValueError):
        hkdf.sha256(b"\x01", b"", b"", 255 * 32 + 1)


def test_token_derivation_shape_is_32_bytes():
    key = hkdf.sha256(bytes.fromhex("00" * 32), bytes.fromhex("10" * 12),
                      b"intel-token-v2\x00", 32)
    assert len(key) == 32
