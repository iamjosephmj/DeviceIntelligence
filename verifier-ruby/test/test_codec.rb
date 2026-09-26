# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "deviceintelligence_verifier"

class CodecTest < Minitest::Test
  FIXTURES = File.expand_path("../../verifiers/fixtures", __dir__)

  def full_session
    DeviceIntelligenceVerifier::ScanSession.new(
      attested_key: "3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb",
      attested_app: DeviceIntelligenceVerifier::AttestedApp.new(
        package_names: ["com.example.app", "com.example.other"],
        signature_digests: ["aa" * 32, "bb" * 32]),
      assurance: "STRONGBOX", boot_state: "Verified", device_locked: true,
      chain_trusted: true, keybox_revoked: false, cross_level_reuse: false,
      device_prop_mismatch: false, boot_state_spoofer: false,
      strongbox_chain_missing: false, software_attested: false,
      os_patch_level: 202604, vendor_patch_level: 20260405, boot_patch_level: 20260405,
      fingerprint: DeviceIntelligenceVerifier::DeviceFingerprint.new(
        id: "cc" * 32, aid: "dd" * 32, security_level: "L1",
        build: "google/raven/raven:16/BP41.250:user/release-keys",
        kernel: "6.1.145-android14-11", patch: "2026-04-05",
        installer: "com.android.vending"))
  end

  def test_a_full_session_round_trips_field_for_field
    codec = DeviceIntelligenceVerifier::ScanSessionCodec
    assert_equal full_session, codec.decode(codec.encode(full_session))
  end

  def test_the_compromised_flags_round_trip
    codec = DeviceIntelligenceVerifier::ScanSessionCodec
    bad = DeviceIntelligenceVerifier::ScanSession.new(
      attested_key: "00", attested_app: nil, assurance: "SOFTWARE",
      boot_state: "Unverified", device_locked: false, chain_trusted: false,
      keybox_revoked: true, cross_level_reuse: true, device_prop_mismatch: true,
      boot_state_spoofer: true, strongbox_chain_missing: true,
      software_attested: true, os_patch_level: nil, vendor_patch_level: nil,
      boot_patch_level: nil, fingerprint: nil)
    assert_equal bad, codec.decode(codec.encode(bad))
  end

  def test_strings_needing_escapes_survive
    codec = DeviceIntelligenceVerifier::ScanSessionCodec
    fp = DeviceIntelligenceVerifier::DeviceFingerprint.new(
      id: nil, aid: nil, security_level: nil, build: 'a"quote\\and/slash',
      kernel: nil, patch: nil, installer: nil)
    odd = DeviceIntelligenceVerifier::ScanSession.new(
      attested_key: "00", attested_app: nil, assurance: "TEE",
      boot_state: "Verified", device_locked: true, chain_trusted: true,
      keybox_revoked: false, cross_level_reuse: false, device_prop_mismatch: false,
      boot_state_spoofer: false, strongbox_chain_missing: false,
      software_attested: false, os_patch_level: nil, vendor_patch_level: nil,
      boot_patch_level: nil, fingerprint: fp)
    assert_equal odd, codec.decode(codec.encode(odd))
  end

  def test_a_session_from_the_python_backend_shape_decodes
    s = DeviceIntelligenceVerifier::ScanSessionCodec.decode(
      File.read(File.join(FIXTURES, "py-session.json")))
    assert_equal "STRONGBOX", s.assurance
    assert_equal "SelfSigned", s.boot_state
    assert s.boot_state_spoofer
    assert s.device_locked
    assert s.chain_trusted
    refute s.keybox_revoked
    refute s.cross_level_reuse
    refute s.device_prop_mismatch
    refute s.software_attested
    assert_equal 202604, s.os_patch_level
    assert_equal 20260405, s.vendor_patch_level
    assert_equal 20260405, s.boot_patch_level
    assert_equal ["tech.thessemaj.deviceintelligence.sample"], s.attested_app.package_names
    assert_equal "L1", s.fingerprint.security_level
    assert_start_with "google/raven/raven:16", s.fingerprint.build
    assert_nil s.fingerprint.installer
  end

  def test_a_malformed_document_is_rejected_rather_than_half_decoded
    assert_raises(ArgumentError, JSON::ParserError) do
      DeviceIntelligenceVerifier::ScanSessionCodec.decode('{"assurance":"TEE"}')
    end
  end

  private

  def assert_start_with(prefix, actual)
    assert actual.start_with?(prefix), "expected #{actual.inspect} to start with #{prefix.inspect}"
  end
end
