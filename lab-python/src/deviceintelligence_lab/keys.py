"""Lab key material: the server X25519 half and the attested leaf key."""
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, NoEncryption


@dataclass(frozen=True)
class ServerKeyPair:
    """The backend's X25519 half: `private_key` for v2 envelope decryption,
    `public_raw` (32 bytes) as the device's server.key content."""
    private_key: x25519.X25519PrivateKey
    private_pem: bytes
    public_raw: bytes


def new_server_keypair() -> ServerKeyPair:
    private = x25519.X25519PrivateKey.generate()
    private_pem = private.private_bytes(Encoding.PEM, serialization.PrivateFormat.PKCS8, NoEncryption())
    public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return ServerKeyPair(private, private_pem, public_raw)


def new_attested_key() -> ec.EllipticCurvePrivateKey:
    """The ECDSA P-256 key the minted leaf attests (the SIG signer)."""
    return ec.generate_private_key(ec.SECP256R1())


def spki_der_hex(public_key) -> str:
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo).hex()
