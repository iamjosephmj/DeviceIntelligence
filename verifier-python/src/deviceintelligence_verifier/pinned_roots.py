"""The pinned Google hardware-attestation roots (PinnedRoots.kt port)."""
import os
from cryptography import x509

def _parse(text: str) -> list:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(x509.load_der_x509_certificate(__import__("base64").b64decode(line)))
    return out

def default() -> list:
    p = os.path.join(os.path.dirname(__file__), "resources", "pinned-roots.txt")
    return _parse(open(p, encoding="utf-8").read())
