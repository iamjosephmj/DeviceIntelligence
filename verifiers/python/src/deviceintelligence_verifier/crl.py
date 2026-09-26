"""Offline keybox-revocation list (AttestationCrl.kt port)."""
import os

def _normalize(serial_hex: str) -> str:
    s = serial_hex.strip().lower().removeprefix("0x").lstrip("0")
    return s or "0"

class AttestationCrl:
    def __init__(self, revoked: set):
        self._revoked = revoked

    def is_revoked(self, cert) -> bool:
        return _normalize(format(cert.serial_number, "x")) in self._revoked

    def first_revoked(self, *chains) -> str | None:
        for chain in chains:
            for cert in chain:
                h = _normalize(format(cert.serial_number, "x"))
                if h in self._revoked:
                    return h
        return None

    @property
    def size(self) -> int:
        return len(self._revoked)

    @staticmethod
    def parse(text: str) -> "AttestationCrl":
        serials = {_normalize(ln.split("#")[0].strip()) for ln in text.splitlines()}
        serials.discard("")
        return AttestationCrl(serials)

    @staticmethod
    def default() -> "AttestationCrl":
        p = os.path.join(os.path.dirname(__file__), "resources", "attestation-crl.txt")
        return AttestationCrl.parse(open(p, encoding="utf-8").read())
