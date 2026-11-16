"""RFC 7748 known-answer tests — via the cryptography library's X25519."""
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

V1_K = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
V1_U = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
V1_O = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
V2_K = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
V2_U = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
V2_O = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
DH_A = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
DH_B = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"


def mult(kh, uh):
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(kh))
    pub = X25519PublicKey.from_public_bytes(bytes.fromhex(uh))
    return priv.exchange(pub).hex()


def test_rfc7748_vector1():
    assert mult(V1_K, V1_U) == V1_O


def test_rfc7748_vector2():
    assert mult(V2_K, V2_U) == V2_O


def test_diffie_hellman_agrees():
    a_pub = X25519PrivateKey.from_private_bytes(bytes.fromhex(DH_A)) \
        .public_key().public_bytes_raw().hex()
    b_pub = X25519PrivateKey.from_private_bytes(bytes.fromhex(DH_B)) \
        .public_key().public_bytes_raw().hex()
    assert a_pub == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert b_pub == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    assert mult(DH_A, b_pub) == SHARED
    assert mult(DH_B, a_pub) == SHARED
