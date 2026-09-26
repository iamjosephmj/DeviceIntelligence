from deviceintelligence_verifier.policy import Policy


def test_critical_severity_blocks():
    assert Policy().is_blocking("INTEL_0001", "CRITICAL")


def test_non_critical_severity_does_not_block_by_default():
    assert not Policy().is_blocking("INTEL_0019", "HIGH")
    assert not Policy().is_blocking("INTEL_0050", "MEDIUM")


def test_allow_list_overrides_severity():
    assert not Policy(allow={"INTEL_0052"}).is_blocking("INTEL_0052", "CRITICAL")


def test_block_list_overrides_severity():
    assert Policy(block={"INTEL_0050"}).is_blocking("INTEL_0050", "MEDIUM")


def test_allow_takes_precedence_over_block():
    p = Policy(allow={"INTEL_0001"}, block={"INTEL_0001"})
    assert not p.is_blocking("INTEL_0001", "CRITICAL")


def test_severity_comparison_is_case_insensitive():
    assert Policy().is_blocking(None, "critical")


def test_null_severity_does_not_block_by_default():
    assert not Policy().is_blocking(None, None)


def test_confirmed_rwx_hook_pool_always_blocks():
    p = Policy(observe_unconfirmed_rwx=True)
    assert p.is_blocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 3)


def test_bare_rwx_downgrades_only_when_opted_in():
    assert Policy().is_blocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0)
    assert not Policy(observe_unconfirmed_rwx=True) \
        .is_blocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0)
