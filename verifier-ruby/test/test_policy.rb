# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

class PolicyTest < Minitest::Test
  def test_critical_severity_blocks
    assert DeviceIntelligenceVerifier::Policy.new.is_blocking("INTEL_0001", "CRITICAL")
  end

  def test_non_critical_severity_does_not_block_by_default
    p = DeviceIntelligenceVerifier::Policy.new
    refute p.is_blocking("INTEL_0019", "HIGH")
    refute p.is_blocking("INTEL_0050", "MEDIUM")
  end

  def test_allow_list_overrides_severity
    p = DeviceIntelligenceVerifier::Policy.new(allow: ["INTEL_0052"])
    refute p.is_blocking("INTEL_0052", "CRITICAL")
  end

  def test_block_list_overrides_severity
    p = DeviceIntelligenceVerifier::Policy.new(block: ["INTEL_0050"])
    assert p.is_blocking("INTEL_0050", "MEDIUM")
  end

  def test_allow_takes_precedence_over_block
    p = DeviceIntelligenceVerifier::Policy.new(allow: ["INTEL_0001"], block: ["INTEL_0001"])
    refute p.is_blocking("INTEL_0001", "CRITICAL")
  end

  def test_severity_comparison_is_case_insensitive
    assert DeviceIntelligenceVerifier::Policy.new.is_blocking(nil, "critical")
  end

  def test_null_severity_does_not_block_by_default
    refute DeviceIntelligenceVerifier::Policy.new.is_blocking(nil, nil)
  end

  def test_confirmed_rwx_hook_pool_always_blocks
    p = DeviceIntelligenceVerifier::Policy.new(observe_unconfirmed_rwx: true)
    assert p.is_blocking("INTEL_0052", "CRITICAL", kind: "rwx_memory_mapping", hook_stub_regions: 3)
  end

  def test_bare_rwx_downgrades_only_when_opted_in
    assert DeviceIntelligenceVerifier::Policy.new.is_blocking(
      "INTEL_0052", "CRITICAL", kind: "rwx_memory_mapping", hook_stub_regions: 0)
    refute DeviceIntelligenceVerifier::Policy.new(observe_unconfirmed_rwx: true).is_blocking(
      "INTEL_0052", "CRITICAL", kind: "rwx_memory_mapping", hook_stub_regions: 0)
  end
end
