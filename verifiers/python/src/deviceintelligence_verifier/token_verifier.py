"""The v1-era verify flow (TokenVerifier.kt port): authenticity + TEE facts."""
import hashlib, json as _json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from .keystream import decrypt_hex
from .models import Check, CheckKind, Decision, VerificationResult
from .chain_verifier import parse_chain as _parse_chain
from .pinned_roots import default as _pinned_default
from .attestation import challenge as _att_challenge, fields as _att_fields
from .signals import resolve as _resolve, device as _device
from .codec import decode as _codec_decode

BINDING_SEP = "\n--BINDING\n"
FS = "\x1F"


class TokenVerifier:
    def __init__(self, registry=None, policy=None, pinned_roots=None):
        from .registry import SignalRegistry
        from .policy import Policy
        self.registry = registry or SignalRegistry.bundled()
        self.policy = policy or Policy()
        self.pinned_roots = pinned_roots or _pinned_default()

    def _parse_chain(self, certs_hex):
        return _parse_chain(certs_hex)

    def verify(self, token_hex: str, issued_nonce: str) -> VerificationResult:
        checks = []
        def auth(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.AUTH)); return ok
        def integ(name, ok, detail=""):
            checks.append(Check(name, ok, detail, CheckKind.INTEGRITY)); return ok

        text = decrypt_hex(token_hex)
        sep = text.find(BINDING_SEP)
        signed = text[:sep] if sep >= 0 else text
        binding = text[sep + len(BINDING_SEP):] if sep >= 0 else ""
        doc = _run(lambda: _json.loads(signed)).get("value") or {}

        if not auth("binding present", sep >= 0, "" if sep >= 0 else "unbound/legacy token"):
            return self._result(checks, doc)
        if not doc:
            auth("signed content is JSON", False, "unparseable signed_content")
            return self._result(checks, doc)

        token_nonce = doc.get("nonce") or ""
        auth("nonce matches issued", token_nonce == issued_nonce)

        sig_hex, certs_hex = "", []
        for line in binding.split("\n"):
            if line.startswith("SIG" + FS): sig_hex = line[4:]
            elif line.startswith("CERT" + FS): certs_hex.append(line[5:])
        if not auth("chain + signature present", bool(sig_hex) and bool(certs_hex)):
            return self._result(checks, doc)

        chain = _run(lambda: _parse_chain(certs_hex)).get("value")
        if not chain:
            auth("chain parses", False, "could not parse cert chain")
            return self._result(checks, doc)
        leaf = chain[0]

        root_err = _run(lambda: self._chain.verify_to_pinned_root(chain) if hasattr(self, "_cv") else
                        _verify_to_pinned(chain, self.pinned_roots))
        auth("chain -> pinned Google root", root_err.get("ok"),
             root_err.get("detail", "") if not root_err.get("ok") else _subject(root_err.get("value")))

        chal = _run(lambda: _att_challenge(leaf))
        auth("attestation challenge == nonce",
             chal.get("ok") and chal["value"].hex() == issued_nonce.lower())

        sig_ok = _run(lambda: leaf.public_key().verify(
            bytes.fromhex(sig_hex), signed.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()))).get("ok", False)
        auth("signature over verdict", sig_ok, "" if sig_ok else "ECDSA verify failed")

        f = _run(lambda: _att_fields(leaf)).get("value")
        integ("hardware security level >= TEE", f is not None and f.security_level in (1, 2),
              f.security_level_name if f else "parse error")
        integ("verified boot state = Verified", f is not None and f.verified_boot_state == 0,
              f.boot_state_name if f else "parse error")
        integ("device locked", f is not None and f.device_locked is True,
              str(f.device_locked) if f else "parse error")

        return self._result(checks, doc)

    def _result(self, checks, doc):
        authentic = all(c.ok for c in checks if c.kind == CheckKind.AUTH)
        device_ok = all(c.ok for c in checks if c.kind == CheckKind.INTEGRITY)
        signals = _resolve(doc, self.registry, self.policy)
        blocking = any(s.blocking for s in signals)
        decision = (Decision.REJECT if not authentic else
                    Decision.COMPROMISED if (not device_ok or blocking) else
                    Decision.TRUSTWORTHY)
        return VerificationResult(decision, authentic, device_ok, checks,
                                  doc.get("schemaVersion"), doc.get("point"), doc.get("ts"),
                                  doc.get("nonce"), _device(doc), signals)


def _run(fn):
    try:
        return {"ok": True, "value": fn()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _verify_to_pinned(chain, pinned_roots):
    from .chain_verifier import verify_to_pinned_root
    return verify_to_pinned_root(chain, pinned_roots)


def _subject(cert):
    return cert.subject.rfc4514_string()


def _att_challenge(leaf):
    from .attestation import challenge
    return challenge(leaf)


def _att_fields(leaf):
    from .attestation import fields
    return fields(leaf)
