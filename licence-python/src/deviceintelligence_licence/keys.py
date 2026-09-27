"""The RVN2 licence blob mint — the pip-installable form of
tools/keys/gen-dev-licence.py, byte-identical to it and to the Kotlin
LicenceKeygen.generate() the SDK's Gradle task wraps."""
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

# The DEV publisher key compiled into dicore/crypto/licence_blob.cpp. Guarded
# against drift by tests/test_licence.py, which reads the native source.
PUBLISHER_KEY = bytes([
    0x8f, 0x2c, 0x1b, 0xa9, 0x40, 0xe7, 0xd3, 0x5c,
    0x6a, 0x1f, 0x0b, 0x8e, 0x2d, 0x4c, 0x9a, 0x37,
    0xb5, 0x63, 0xe0, 0x11, 0x7a, 0xc8, 0x94, 0x2f,
    0x0d, 0x56, 0xab, 0x38, 0xe4, 0x71, 0x9c, 0x60,
])


@dataclass(frozen=True)
class LicenceMaterial:
    server_key: bytes          # 144 bytes — PUBLIC, ships at assets/tech.thessemaj.deviceintelligence/server.key
    private_pem: bytes         # backend half — decrypts every emitted token
    public_raw_hex: str
    epoch: int
    not_after: int


def build_blob(application_id: str, *, epoch: int = 0, not_after: int = 0,
               private_key: X25519PrivateKey,
               publisher_key: bytes = PUBLISHER_KEY) -> bytes:
    """The 144-byte RVN2 blob:
    magic(4) ver(1) epoch(1) curve(1) flags(1) pubkey(32) pkgHash(32)
    notAfter(8, big-endian) || HMAC-SHA256(publisherKey, body)(32) || reserved(32)."""
    if not 0 <= epoch <= 255:
        raise ValueError("epoch must be 0..255")
    raw_pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    body = bytearray(80)
    body[0:4] = b"RVN2"
    body[4] = 0x02
    body[5] = epoch
    body[6] = 0x01                       # curve: X25519
    body[7] = 0x00                       # flags
    body[8:40] = raw_pub
    body[40:72] = hashlib.sha256(application_id.encode("utf-8")).digest()
    body[72:80] = not_after.to_bytes(8, "big")
    tag = hmac.new(publisher_key, bytes(body), hashlib.sha256).digest()
    return bytes(body) + tag + bytes(32)


def generate_licence(application_id: str, *, epoch: int = 0, not_after: int = 0,
                     out_dir=None, private_key: X25519PrivateKey | None = None,
                     publisher_key: bytes = PUBLISHER_KEY) -> LicenceMaterial:
    """A fresh keypair + licence. With [out_dir], writes `server.key` and
    `server-priv-<epoch>.pem` (chmod 600) exactly like the reference script."""
    if not 0 <= epoch <= 255:
        raise ValueError("epoch must be 0..255")
    private_key = private_key or X25519PrivateKey.generate()
    blob = build_blob(application_id, epoch=epoch, not_after=not_after,
                      private_key=private_key, publisher_key=publisher_key)
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    if out_dir is not None:
        out_dir = os.fspath(out_dir)
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "server.key"), "wb") as f:
            f.write(blob)
        pem_path = os.path.join(out_dir, f"server-priv-{epoch}.pem")
        with open(pem_path, "wb") as f:
            f.write(pem)
        os.chmod(pem_path, 0o600)
    raw_pub = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return LicenceMaterial(blob, pem, raw_pub.hex(), epoch, not_after)
