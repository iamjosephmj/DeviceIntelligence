"""Mints a lab attestation identity: a stable root + intermediate, and a
fresh attestation leaf per token (the KeyDescription challenge must equal
the token's nonce — challenge-bound freshness). The pinned-roots text makes
the chain acceptable to a verifier; against Google's bundled roots it must
(and does) REJECT."""
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from .key_description import ATTESTATION_OID, key_description_der
from .keys import new_attested_key, spki_der_hex

ROOT_CN = "DI Lab Attestation Root"
INTERMEDIATE_CN = "DI Lab Attestation Intermediate"
LEAF_CN = "DI Lab Attestation Leaf"


@dataclass(frozen=True)
class MintedLeaf:
    """One attestation leaf: the certificate, and the key that must sign the
    token's SIG line (the verifier checks the SIG with the leaf's key)."""
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def der_hex(self) -> str:
        return self.cert.public_bytes(Encoding.DER).hex()

    @property
    def spki_hex(self) -> str:
        return spki_der_hex(self.key.public_key())


@dataclass(frozen=True)
class MintedChain:
    intermediate: x509.Certificate
    intermediate_key: ec.EllipticCurvePrivateKey
    root: x509.Certificate
    pinned_roots_text: str

    @classmethod
    def mint(cls) -> "MintedChain":
        intermediate_key, root_key = new_attested_key(), new_attested_key()
        not_before = datetime.now(timezone.utc) - timedelta(days=1)
        not_after = not_before + timedelta(days=365)
        root = _cert(ROOT_CN, root_key, ROOT_CN, root_key, not_before, not_after, is_ca=True)
        intermediate = _cert(INTERMEDIATE_CN, intermediate_key, ROOT_CN, root_key,
                             not_before, not_after, is_ca=True)
        pinned = ("# DI lab attestation root — pin it: the verifier REJECTs this\n"
                  "# chain against the bundled Google roots, and must.\n"
                  + base64.b64encode(root.public_bytes(Encoding.DER)).decode() + "\n")
        return cls(intermediate, intermediate_key, root, pinned)

    def mint_leaf(
        self,
        *,
        challenge: bytes,
        verified_boot_state: int = 0,
        device_locked: bool = True,
        security_level: int = 1,
        leaf_common_name: str = LEAF_CN,
        days: int = 365,
    ) -> MintedLeaf:
        """A fresh attestation leaf carrying [challenge]; the leaf options
        are the TEE's word — flip them to mint a spoofed-device token."""
        key = new_attested_key()
        not_before = datetime.now(timezone.utc) - timedelta(days=1)
        key_description = key_description_der(
            challenge=challenge,
            security_level=security_level,
            device_locked=device_locked,
            verified_boot_state=verified_boot_state,
        )
        cert = _cert(leaf_common_name, key, INTERMEDIATE_CN, self.intermediate_key,
                     not_before, not_before + timedelta(days=days), is_ca=False,
                     attestation_der=key_description)
        return MintedLeaf(cert, key)


def _cert(cn, subject_key, issuer_cn, issuer_key, not_before, not_after,
          *, is_ca, attestation_der=None) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (x509.CertificateBuilder()
               .subject_name(name)
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
               .public_key(subject_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True))
    if attestation_der is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(ATTESTATION_OID), attestation_der),
            critical=False)
    return builder.sign(issuer_key, hashes.SHA256())
