"""Decrypts a token and returns its document WITHOUT verifying (TokenDecoder.kt port)."""
import json as _json
from .keystream import decrypt_hex
from .signals import resolve, device

BINDING_SEP = "\n--BINDING\n"


class TokenDecoder:
    def __init__(self, registry=None, policy=None):
        from .registry import SignalRegistry
        from .policy import Policy
        self.registry = registry or SignalRegistry.bundled()
        self.policy = policy or Policy()

    def decode(self, token_hex: str):
        text = decrypt_hex(token_hex)
        idx = text.find(BINDING_SEP)
        signed = text[:idx] if idx >= 0 else text
        doc = _json.loads(signed)
        from .models import DecodedToken
        return DecodedToken(
            schema_version=doc.get("schemaVersion"), point=doc.get("point"),
            ts=doc.get("ts"), nonce=doc.get("nonce"),
            device=device(doc), signals=resolve(doc, self.registry, self.policy),
            has_binding=idx >= 0,
        )
