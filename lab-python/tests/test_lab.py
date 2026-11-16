"""The lab contract: everything minted here must verify through
deviceintelligence-verifier exactly like a real capture."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "verifier-python", "src"))

from deviceintelligence_verifier.attestation.pinned_roots import _parse as parse_pinned
from deviceintelligence_verifier.tokens.token_crypto import decrypt as v2_decrypt
from deviceintelligence_verifier.tokens.token_verifier import TokenVerifier

from deviceintelligence_lab import MintedChain, TokenIssuer, new_server_keypair
from deviceintelligence_lab.tokens import seal_v2, encrypt_hex as v1_encrypt


@pytest.fixture(scope="module")
def honest_chain():
    return MintedChain.mint()


@pytest.fixture(scope="module")
def spoofed_chain():
    return MintedChain.mint()


SPOOFED_LEAF = dict(verified_boot_state=2, device_locked=False)


@pytest.fixture(scope="module")
def verifier(honest_chain):
    return TokenVerifier(pinned_roots=parse_pinned(honest_chain.pinned_roots_text))


def test_honest_v1_token_is_trustworthy(honest_chain, verifier):
    issuer = TokenIssuer(honest_chain)
    issued = issuer.issue(session_id="s-1")
    res = verifier.verify(issued.token_hex, issued.nonce_hex)
    assert res.decision.value == "TRUSTWORTHY"
    assert res.authentic
    assert res.device_integrity_ok


def test_issued_nonce_round_trips_through_signed_content(honest_chain, verifier):
    issuer = TokenIssuer(honest_chain)
    issued = issuer.issue(session_id="s-2")
    doc = json.loads(issued.signed_content)
    assert doc["nonce"] == issued.nonce_hex
    assert doc["sessionId"] == "s-2"
    assert doc["attestedKey"] == issued.leaf_spki_hex


def test_spoofed_chain_is_compromised_but_authentic(spoofed_chain):
    verifier = TokenVerifier(pinned_roots=parse_pinned(spoofed_chain.pinned_roots_text))
    issued = TokenIssuer(spoofed_chain).issue(session_id="s-3", **SPOOFED_LEAF)
    res = verifier.verify(issued.token_hex, issued.nonce_hex)
    assert res.authentic
    assert not res.device_integrity_ok
    assert res.decision.value == "COMPROMISED"


def test_v2_envelope_decrypts_to_the_same_plaintext(honest_chain, verifier):
    server = new_server_keypair()
    issuer = TokenIssuer(honest_chain)
    plain = issuer.build_plaintext(session_id="s-4")
    token = seal_v2(plain, server.public_raw)
    assert v2_decrypt(token, server.private_key) == plain.encode("utf-8")


def test_tampered_token_is_rejected(honest_chain, verifier):
    issued = TokenIssuer(honest_chain).issue(session_id="s-5")
    # Flip the first hex character: deterministic corruption of the JSON's
    # opening byte, so the signed content can never parse.
    first, rest = issued.token_hex[0], issued.token_hex[1:]
    tampered = ("0" if first != "0" else "1") + rest
    res = verifier.verify(tampered, issued.nonce_hex)
    assert res.decision.value == "REJECT"
    assert not res.authentic


def test_chain_must_be_pinned(honest_chain):
    # The lab root is NOT a Google root: against the bundled pins, REJECT.
    google_verifier = TokenVerifier()
    issued = TokenIssuer(honest_chain).issue(session_id="s-6")
    res = google_verifier.verify(issued.token_hex, issued.nonce_hex)
    assert res.decision.value == "REJECT"


def test_pinned_roots_text_parses_as_verifier_roots(honest_chain):
    roots = parse_pinned(honest_chain.pinned_roots_text)
    assert len(roots) == 1
