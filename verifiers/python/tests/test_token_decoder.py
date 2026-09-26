from pathlib import Path
from deviceintelligence_verifier.token_decoder import TokenDecoder

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def test_decodes_real_challenge_token_fixture():
    d = TokenDecoder().decode((FIXTURES / "pixel-challenge.token").read_text().strip())
    assert d.schema_version == 3
    assert d.has_binding


def _resolve(doc):
    from deviceintelligence_verifier.signals import resolve as _resolve
    from deviceintelligence_verifier.policy import Policy
    from deviceintelligence_verifier.registry import SignalRegistry
    return _resolve(doc, SignalRegistry.bundled(), Policy())


def test_resolve_maps_known_signal_from_registry():
    doc = {"signals": [{"id": "INTEL_0052", "detail": "x"}]}
    out = _resolve(doc)
    assert out[0].id == "INTEL_0052" and out[0].detector != "?" and out[0].detail == "x"


def test_resolve_falls_back_for_unknown_signal():
    doc = {"signals": [{"id": "INTEL_9999", "severity": "CRITICAL"}]}
    out = _resolve(doc)
    assert out[0].id == "INTEL_9999" and out[0].detector == "?" and out[0].severity == "CRITICAL"


def test_device_parses_when_present_and_null_when_absent():
    from deviceintelligence_verifier.signals import device
    d = device({"device": {"api": 34, "abi": "arm64-v8a", "model": "Pixel"}})
    assert d.api == 34 and d.abi == "arm64-v8a" and d.model == "Pixel"
    assert device({}) is None
