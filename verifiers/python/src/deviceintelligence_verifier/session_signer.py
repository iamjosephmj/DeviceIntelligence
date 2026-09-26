"""Stateless HMAC session tokens (SessionSigner.kt port)."""
import base64, hashlib, hmac, json, time
from .models import Assurance, Session

DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60

class SessionSigner:
    def __init__(self, server_key: bytes, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
                 now=None):
        self._key, self._max_age = server_key, max_age_seconds
        self._now = now or (lambda: int(time.time()))

    def issue(self, s: Session) -> str:
        payload = json.dumps({
            "pinnedKey": s.pinned_key_spki_hex, "assurance": s.assurance.name,
            "boot": s.boot_state, "locked": s.device_locked, "issuedAt": s.issued_at,
            "chainTrusted": s.chain_trusted, "kbRevoked": s.keybox_revoked,
            "xlReuse": s.cross_level_reuse, "sbMissing": s.strongbox_chain_missing,
            "propMismatch": s.device_prop_mismatch, "bootSpoofer": s.boot_state_spoofer,
            "swAttest": s.software_attested,
        }, separators=(",", ":")).encode()
        b64 = base64.urlsafe_b64encode
        return (b64(payload).rstrip(b"=").decode() + "." +
                b64(self._mac(payload)).rstrip(b"=").decode())

    def open(self, session_id: str) -> Session | None:
        try:
            payload_b64, mac_b64 = session_id.split(".", 1)
            pad = lambda s: s + "=" * (-len(s) % 4)
            payload = base64.urlsafe_b64decode(pad(payload_b64))
            got = base64.urlsafe_b64decode(pad(mac_b64))
            if not hmac.compare_digest(self._mac(payload), got):
                return None
            o = json.loads(payload)
            issued_at = o["issuedAt"]
            if not isinstance(issued_at, int) or issued_at <= 0 or \
               self._now() - issued_at > self._max_age:
                return None
            return Session(
                pinned_key_spki_hex=o["pinnedKey"],
                assurance=Assurance[o["assurance"]],
                boot_state=o["boot"], device_locked=o["locked"], issued_at=issued_at,
                chain_trusted=o.get("chainTrusted", True),
                keybox_revoked=o.get("kbRevoked", False),
                cross_level_reuse=o.get("xlReuse", False),
                strongbox_chain_missing=o.get("sbMissing", False),
                device_prop_mismatch=o.get("propMismatch", False),
                boot_state_spoofer=o.get("bootSpoofer", False),
                software_attested=o.get("swAttest", False))
        except Exception:
            return None

    def _mac(self, data: bytes) -> bytes:
        import hmac as h
        return h.new(self._key, data, hashlib.sha256).digest()
