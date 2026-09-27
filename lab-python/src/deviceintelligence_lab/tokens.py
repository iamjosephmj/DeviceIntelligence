"""Token issuance: signed_content + --BINDING + SIG/CERT lines, in the v1
keystream envelope (the form every port's TokenVerifier.verify consumes) or
as raw plaintext for the v2 ECIES envelope (seal_v2)."""
import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .keystream import encrypt_hex

BINDING_SEP = "\n--BINDING\n"
FS = "\x1f"
V2_PREFIX = "2:"
V2_INFO = b"intel-token-v2"


@dataclass(frozen=True)
class IssuedToken:
    token_hex: str
    nonce_hex: str
    signed_content: str
    leaf_spki_hex: str


class TokenIssuer:
    def __init__(self, chain, *, schema_version: int = 3):
        self.chain = chain
        self.schema_version = schema_version

    def issue(self, session_id: str = "lab-session", extra: dict | None = None,
              **leaf_options) -> IssuedToken:
        """A complete v1 token: decrypt_hex(token) equals the assembled
        plaintext. [leaf_options] flip the TEE's word (spoofed devices)."""
        plaintext, nonce_hex, signed, leaf = self._assemble(session_id, extra, leaf_options)
        return IssuedToken(encrypt_hex(plaintext), nonce_hex, signed, leaf.spki_hex)

    def build_plaintext(self, session_id: str = "lab-session",
                        extra: dict | None = None, **leaf_options) -> str:
        """The unencrypted wire layout — the payload `seal_v2` envelopes."""
        plaintext, _, _, _ = self._assemble(session_id, extra, leaf_options)
        return plaintext

    def _assemble(self, session_id, extra, leaf_options):
        nonce_hex = os.urandom(32).hex()
        leaf = self.chain.mint_leaf(challenge=bytes.fromhex(nonce_hex), **leaf_options)
        doc = {"schemaVersion": self.schema_version,
               "sessionId": session_id,
               "attestedKey": leaf.spki_hex,
               "nonce": nonce_hex}
        doc.update(extra or {})
        signed = json.dumps(doc, separators=(",", ":"), sort_keys=True)
        lines = [f"SIG{FS}{leaf.key.sign(signed.encode('utf-8'), ec.ECDSA(hashes.SHA256())).hex()}"]
        lines += [f"CERT{FS}{leaf.der_hex}",
                  f"CERT{FS}{_hex(self.chain.intermediate)}",
                  f"CERT{FS}{_hex(self.chain.root)}"]
        plaintext = signed + BINDING_SEP + "\n".join(lines) + "\n"
        return plaintext, nonce_hex, signed, leaf


def seal_v2(plaintext: str, server_public_raw: bytes, *, epoch: int = 1) -> str:
    """The v2 ECIES envelope: '2:' + hex(version || epoch || eph_pub || nonce || ct||tag)."""
    version = 2
    ephemeral = x25519.X25519PrivateKey.generate()
    eph_pub = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = os.urandom(12)
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(server_public_raw))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce,
               info=V2_INFO + bytes([epoch])).derive(shared)
    aad = bytes([version, epoch]) + eph_pub
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return V2_PREFIX + (bytes([version, epoch]) + eph_pub + nonce + ct).hex()


def _hex(cert) -> str:
    return cert.public_bytes(Encoding.DER).hex()
