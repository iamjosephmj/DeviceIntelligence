# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

class TokenDecoderTest < Minitest::Test
  FIXTURES = File.expand_path("../../verifiers/fixtures", __dir__)

  def test_decodes_real_challenge_token_fixture
    token = File.read(File.join(FIXTURES, "pixel-challenge.token")).strip
    d = DeviceIntelligenceVerifier::TokenDecoder.new.decode(token)
    assert_equal 3, d.schema_version
    assert d.has_binding
  end

  def test_resolve_maps_known_signal_from_registry
    doc = { "signals" => [{ "id" => "INTEL_0052", "detail" => "x" }] }
    out = DeviceIntelligenceVerifier::Signals.resolve(
      doc, DeviceIntelligenceVerifier::SignalRegistry.bundled,
      DeviceIntelligenceVerifier::Policy.new)
    assert_equal "INTEL_0052", out[0].id
    refute_equal "?", out[0].detector
    assert_equal "x", out[0].detail
  end

  def test_resolve_falls_back_for_unknown_signal
    doc = { "signals" => [{ "id" => "INTEL_9999", "severity" => "CRITICAL" }] }
    out = DeviceIntelligenceVerifier::Signals.resolve(
      doc, DeviceIntelligenceVerifier::SignalRegistry.bundled,
      DeviceIntelligenceVerifier::Policy.new)
    assert_equal "INTEL_9999", out[0].id
    assert_equal "?", out[0].detector
    assert_equal "CRITICAL", out[0].severity
  end

  def test_device_parses_when_present_and_nil_when_absent
    d = DeviceIntelligenceVerifier::Signals.device(
      { "device" => { "api" => 34, "abi" => "arm64-v8a", "model" => "Pixel" } })
    assert_equal 34, d.api
    assert_equal "arm64-v8a", d.abi
    assert_equal "Pixel", d.model
    assert_nil DeviceIntelligenceVerifier::Signals.device({})
  end
end
