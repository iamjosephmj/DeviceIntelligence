from deviceintelligence_verifier.models import Decision, ResolvedSignal, ScanResult


def signal(sid, blocking):
    return ResolvedSignal(id=sid, detector="t", kind="t", title="", severity="HIGH",
                          detail="", blocking=blocking)


def result(ok, device_integrity_ok=True, signals=None):
    return ScanResult(ok=ok, bootstrap=False, device_integrity_ok=device_integrity_ok,
                      session=None, checks=[], signals=signals or [],
                      reason=None if ok else "forgery")


def test_a_proven_forgery_is_rejected_even_if_everything_else_looks_clean():
    assert result(False).decision == Decision.REJECT


def test_an_untrustworthy_device_is_compromised_not_rejected():
    assert result(True, device_integrity_ok=False).decision == Decision.COMPROMISED


def test_a_blocking_signal_is_compromised():
    assert result(True, signals=[signal("INTEL_0025", True)]).decision == Decision.COMPROMISED


def test_a_non_blocking_signal_stays_trustworthy():
    assert result(True, signals=[signal("INTEL_0056", False)]).decision == Decision.TRUSTWORTHY


def test_clean_scan_is_trustworthy():
    assert result(True).decision == Decision.TRUSTWORTHY


def test_blocking_signals_carries_only_the_blocking_findings():
    r = result(True, signals=[signal("INTEL_0056", False), signal("INTEL_0025", True),
                              signal("INTEL_0044", True)])
    assert [s.id for s in r.blocking_signals] == ["INTEL_0025", "INTEL_0044"]


def test_forgery_wins_over_everything():
    r = result(False, device_integrity_ok=False, signals=[signal("INTEL_0025", True)])
    assert r.decision == Decision.REJECT
