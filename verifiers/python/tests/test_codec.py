import json
from pathlib import Path
import pytest
from deviceintelligence_verifier.codec import decode, encode
from deviceintelligence_verifier.models import (Assurance, AttestedApp, DeviceFingerprint, ScanSession)
    
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def full_session():
    return ScanSession(
        attested_key="3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb",
        attested_app=AttestedApp(package_names=["com.example.app", "com.example.other"],
                                 signature_digests=["aa" * 32, "bb" * 32]),
        assurance=Assurance.STRONGBOX, boot_state="Verified", device_locked=True,
        chain_trusted=True, os_patch_level=202604, vendor_patch_level=20260405,
        boot_patch_level=20260405,
        fingerprint=DeviceFingerprint(id="cc" * 32, aid="dd" * 32, security_level="L1",
                                      build="google/raven/raven:16/BP41.250:user/release-keys",
                                      kernel="6.1.145-android14-11", patch="2026-04-05",
                                      installer="com.android.vending"))


def test_a_full_session_round_trips_field_for_field():
    assert decode(encode(full_session())) == full_session()


def test_the_compromised_flags_round_trip():
    bad = ScanSession(assured := None or "00", None, Assurance.SOFTWARE, "Unverified", False,
                      chain_trusted=False, keybox_revoked=True, cross_level_reuse=True,
                      device_prop_mismatch=True, boot_state_spoofer=True,
                      strongbox_chain_missing=True, software_attested=True)
    assert decode(encode(bad)) == bad


def test_the_nullable_fields_round_trip_as_null():
    sparse = ScanSession(attested_key="00", attested_app=None, assurance=Assurance.TEE,
                         boot_state="Verified", device_locked=True)
    assert decode(encode(sparse)) == sparse


def test_strings_needing_escapes_survive():
    odd = ScanSession(attested_key="00", attested_app=None, assurance=Assurance.TEE,
                      boot_state="Verified", device_locked=True,
                      fingerprint=DeviceFingerprint(id=None, aid=None, security_level=None,
                                                    build='a"quote\\and/slash', kernel=None,
                                                    patch=None, installer=None))
    assert decode(encode(odd)) == odd


def test_a_session_from_the_python_backend_shape_decodes():
    s = decode((FIXTURES / "py-session.json").read_text())
    assert s.assurance == Assurance.STRONGBOX
    assert s.boot_state == "SelfSigned"
    assert s.boot_state_spoofer and s.device_locked and s.chain_trusted
    assert not s.keybox_revoked and not s.cross_level_reuse
    assert not s.device_prop_mismatch and not s.software_attested
    assert s.os_patch_level == 202604 and s.vendor_patch_level == 20260405
    assert s.boot_patch_level == 20260405
    assert s.attested_app.package_names == ["tech.thessemaj.deviceintelligence.sample"]
    assert s.fingerprint.security_level == "L1"
    assert s.fingerprint.build.startswith("google/raven/raven:16")
    assert s.fingerprint.installer is None


def test_a_malformed_document_is_rejected_rather_than_half_decoded():
    with pytest.raises(ValueError):
        decode('{"assurance":"TEE"}')
