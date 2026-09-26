from deviceintelligence_verifier.models import AttestationFields
from deviceintelligence_verifier.scan_verifier import boot_state_spoofer


def att(boot, locked):
    return AttestationFields(security_level=2, verified_boot_state=boot, device_locked=locked)


def test_flags_spoofer_props_clean_attestation_dirty():
    reported = {"vbs": "green", "blocked": "1", "vbmeta": "locked"}
    assert boot_state_spoofer(reported, att(2, False))


def test_flags_spoofer_via_locked_props_without_green():
    reported = {"vbs": "", "blocked": "1", "vbmeta": "locked"}
    assert boot_state_spoofer(reported, att(2, False))


def test_flags_spoofer_via_vbmeta_only():
    reported = {"vbs": "green", "blocked": "", "vbmeta": "locked"}
    assert boot_state_spoofer(reported, att(3, False))


def test_passes_genuine_locked_device():
    reported = {"vbs": "green", "blocked": "1", "vbmeta": "locked"}
    assert not boot_state_spoofer(reported, att(0, True))


def test_does_not_flag_plain_unlocked_device():
    reported = {"vbs": "orange", "blocked": "0", "vbmeta": "unlocked"}
    assert not boot_state_spoofer(reported, att(2, False))


def test_no_self_report_is_not_flagged():
    assert not boot_state_spoofer({}, att(0, True))
    assert not boot_state_spoofer({}, att(2, False))


def test_clean_claim_with_no_attestation_is_flagged():
    assert boot_state_spoofer({"vbs": "green", "blocked": "1"}, None)
