"""Token attestation chain validation (ChainVerifier.kt port)."""
import hashlib
from cryptography import x509

def parse_chain(certs_hex: list) -> list:
    return [x509.load_der_x509_certificate(bytes.fromhex(h)) for h in certs_hex]

def _sha256_fp(cert) -> bytes:
    return hashlib.sha256(cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER)).digest()

def _verify_signed_by(cert, issuer) -> None:
    """Signature-only verification with the issuer's own algorithm: Pixel
    attestation chains mix EC keyboxes with RSA Google intermediates/roots."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
    from cryptography.hazmat.primitives import hashes
    pub = issuer.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
                   hashes.SHA256())
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("unsupported issuer key type")


def verify_to_pinned_root(chain: list, pinned_roots: list):
    """Returns the pinned root the chain terminates in, or raises ValueError."""
    if not chain:
        raise ValueError("empty chain")
    for i in range(len(chain) - 1):
        _verify_signed_by(chain[i], chain[i + 1])
    top = chain[-1]
    top_fp = _sha256_fp(top)
    for root in pinned_roots:
        if top_fp == _sha256_fp(root):
            return root
        try:
            _verify_signed_by(top, root)
            return root
        except Exception:
            continue
    raise ValueError("chain top does not chain to a pinned Google root")


def parse_chain_pem(certs_pem: list) -> list:
    from cryptography import x509
    return [x509.load_pem_x509_certificate(p.encode()) for p in certs_pem]
