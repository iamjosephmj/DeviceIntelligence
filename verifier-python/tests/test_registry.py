from deviceintelligence_verifier.registry import SignalRegistry

REG = SignalRegistry.bundled()


def test_bundled_registry_loads_the_active_rows():
    assert REG.size == 61


def test_resolves_a_code_to_its_meaning():
    meta = REG["INTEL_0042"]
    assert meta.detector == "native_integrity"
    assert meta.kind == "text_integrity_divergence"
    assert meta.severity == "CRITICAL"


def test_retired_codes_are_absent():
    assert REG["INTEL_0020"] is None   # keybox_injection, retired
    assert REG["INTEL_0039"] is None   # strongbox_downgrade_suspected, retired


def test_unknown_codes_resolve_to_question_marks():
    row = SignalRegistry.from_json('{"signals":[{"id":"INTEL_9999"}]}')["INTEL_9999"]
    assert row.detector == "?" and row.kind == "?"


def test_null_safe_get():
    assert REG[None] is None
