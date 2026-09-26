"""v2 ECIES token crypto (TokenCryptoV2.kt port) + the v1 keystream discriminator."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib
from . import keystream

PREFIX = "2:"
INFO_PREFIX = b"intel-token-v2"
HEADER = 1 + 1 + 32 + 12
TAG = 16


def is_v2(token: str) -> bool:
    """A v1 token is pure lowercase hex (no ':'); v2 carries the '2:' discriminator."""
    return token.startswith(PREFIX)


def decrypt(token_v2: str, server_scalar_or_priv) -> bytes:
    """Decrypt a '2:' token with the server X25519 private scalar.

    Raises InvalidTag on tamper, ValueError if malformed. Never returns plaintext
    on any tamper: every corruption fails the GCM tag.
    """
    if not token_v2.startswith(PREFIX):
        raise ValueError("not a v2 token")
    body = token_v2[len(PREFIX):]
    if len(body) % 2 != 0:
        raise ValueError("odd-length hex")
    try:
        p = bytes.fromhex(body)
    except ValueError:
        raise ValueError("bad hex char")
    if len(p) < HEADER + TAG:
        raise ValueError("v2 token too short")

    version, epoch = p[0], p[1]
    eph_pub, nonce = p[2:34], p[34:46]
    ct_and_tag = p[HEADER:]

    scalar = _scalar_of(server_scalar_or_priv)
    eph = bytearray(eph_pub)
    eph[31] &= 0x7F                       # RFC 7748: the ignored high bit
    shared = X25519PrivateKey.from_private_bytes(bytes(scalar)) \
        .exchange(X25519PublicKey.from_public_bytes(bytes(eph)))
    key = _hkdf_sha256(shared, nonce, INFO_PREFIX + bytes([epoch]), 32)

    aad = bytes([version, epoch]) + eph_pub
    return AESGCM(key).decrypt(nonce, ct_and_tag, aad)


def _scalar_of(key):
    from cryptography.hazmat.primitives.serialization import PrivateFormat
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    if isinstance(key, X25519PrivateKey):
        return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt,
                info=info).derive(ikm)


