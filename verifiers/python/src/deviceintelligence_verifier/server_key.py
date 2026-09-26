"""Loads the backend X25519 private half (ServerKey.kt port)."""
import base64, hashlib, os, threading
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key

_cache, _lock = {}, threading.Lock()

def from_pkcs8(der: bytes):
    """cryptography parses X25519 PKCS#8 directly; a truncated tail-32 fallback
    mirrors the Kotlin no-XDH path for exotic encodings."""
    try:
        return load_der_private_key(der, password=None)
    except Exception:
        if len(der) < 32:
            raise ValueError(f"PKCS#8 X25519 key too short: {len(der)} bytes")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        return X25519PrivateKey.from_private_bytes(der[-32:])

def from_pem(pem: str):
    cleaned = (pem.replace("-----BEGIN PRIVATE KEY-----", "")
                  .replace("-----END PRIVATE KEY-----", "")
                  .replace("-----BEGIN ", "").replace("-----END ", ""))
    cleaned = "".join(cleaned.split())
    return from_pkcs8(base64.b64decode(cleaned))

def from_bytes(data: bytes):
    digest = hashlib.sha256(data).hexdigest()
    with _lock:
        if digest not in _cache:
            text = data.decode("ascii", errors="ignore")
            _cache[digest] = from_pem(text) if "-----BEGIN" in text else from_pkcs8(data)
    return _cache[digest]

def from_file(path: str):
    with open(path, "rb") as f:
        return from_bytes(f.read())
