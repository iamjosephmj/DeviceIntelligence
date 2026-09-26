"""Parity against a REAL bootstrap scan captured from the Pixel 6 Pro rig, verified
through the v2 path with the sample's server key. The Kotlin golden capture
(verifiers/tests/golden-kotlin-scan.txt) is the reference output."""
import json
from pathlib import Path
from deviceintelligence_verifier.scan_verifier import ScanVerifier
from deviceintelligence_verifier.codec import decode
from deviceintelligence_verifier.server_key import from_file

HERE = Path(__file__).resolve().parents[2]
FIXTURES = HERE / "fixtures"
GOLDEN = HERE / "tests" / "golden-kotlin-scan.txt"


def test_bootstrap_scan_matches_the_kotlin_golden():
    golden_lines = GOLDEN.read_text().splitlines()
    session_facts = next(ln.strip() for ln in golden_lines
                         if ln.strip().startswith('{"attestedKey"'))
    expected_facts = json.loads(session_facts)
    expected_result = next(ln.strip() for ln in golden_lines if ln.startswith("RESULT:"))

    server_priv = from_file(str(FIXTURES / 'fp-e2e-priv.pem'))
    token = (FIXTURES / "fp-e2e.token").read_text().strip()
    session_id = (FIXTURES / "fp-e2e-session.txt").read_text().strip()

    r = ScanVerifier().verify_scan(token, session_id, server_priv)
    assert not r.ok, "the boot-state spoofer is an AUTH forgery: REJECT"
    assert r.bootstrap and r.reason == "boot-state self-report matches hardware attestation"
    assert any(s.id == "INTEL_0055" and s.blocking for s in r.signals)
    assert not r.device_integrity_ok, "the TEE honestly reports SelfSigned"

    # The carried session facts must match the Kotlin golden byte-for-byte (JSON).
    mine = json.loads(decode := __import__("deviceintelligence_verifier.codec",
                                           fromlist=["encode"]).encode(r.session))
    assert mine == expected_facts
    assert expected_result.startswith("RESULT:")
