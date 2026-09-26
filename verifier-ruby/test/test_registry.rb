# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

class RegistryTest < Minitest::Test
  def reg
    DeviceIntelligenceVerifier::SignalRegistry.bundled
  end

  def test_bundled_registry_loads_the_active_rows
    assert_equal 61, reg.size
  end

  def test_resolves_a_code_to_its_meaning
    meta = reg.get("INTEL_0042")
    assert_equal "native_integrity", meta.detector
    assert_equal "text_integrity_divergence", meta.kind
    assert_equal "CRITICAL", meta.severity
  end

  def test_retired_codes_are_absent
    assert_nil reg.get("INTEL_0020")   # keybox_injection, retired
    assert_nil reg.get("INTEL_0039")   # strongbox_downgrade_suspected, retired
  end

  def test_unknown_codes_resolve_to_question_marks
    row = DeviceIntelligenceVerifier::SignalRegistry
          .from_json('{"signals":[{"id":"INTEL_9999"}]}').get("INTEL_9999")
    assert_equal "?", row.detector
    assert_equal "?", row.kind
  end

  def test_null_safe_get
    assert_nil reg.get(nil)
  end
end
