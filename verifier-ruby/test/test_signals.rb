# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "deviceintelligence_verifier"

class SignalsTest < Minitest::Test
  def reg
    @reg ||= DeviceIntelligenceVerifier::SignalRegistry.bundled
  end

  def pol
    @pol ||= DeviceIntelligenceVerifier::Policy.new
  end

  def test_resolves_enrichment_attributes
    doc = JSON.parse('{"signals":[{"id":"INTEL_0044","severity":"HIGH","detail":"Injected ' \
                     'native library. path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so ' \
                     'module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}')
    sig = DeviceIntelligenceVerifier::Signals.resolve(doc, reg, pol)[0]
    assert_equal "evilmod", sig.attributes["module_id"]
    assert_equal "liblog.so,libc.so", sig.attributes["needed"]
    assert_equal "libdobby.so", sig.attributes["links_hook_lib"]
    assert_equal "/data/adb/modules/evilmod/zygisk/arm64-v8a.so", sig.attributes["path"]
  end

  def test_resolves_got_hijack_symbol_attributes
    doc = JSON.parse('{"signals":[{"id":"INTEL_0031","severity":"CRITICAL","detail":"hooked ' \
                     'function pointer. lib=/system/lib64/libbinder.so hooked_symbol=ioctl ' \
                     'hooked_by=evilmod"}]}')
    sig = DeviceIntelligenceVerifier::Signals.resolve(doc, reg, pol)[0]
    assert_equal "ioctl", sig.attributes["hooked_symbol"]
    assert_equal "evilmod", sig.attributes["hooked_by"]
  end

  def test_correlates_definitive_hook_structural_plus_behavioral
    doc = JSON.parse('{"signals":[{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline ' \
                     'hook. hooked_symbol=faccessat hooked_by=evilmod"},{"id":"INTEL_0059",' \
                     '"severity":"HIGH","detail":"lie. hooked_symbol=faccessat ' \
                     'path=/system/bin/sh"},{"id":"INTEL_0003","severity":"CRITICAL",' \
                     '"detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}]}')
    resolved = DeviceIntelligenceVerifier::Signals.resolve(doc, reg, pol)
    assert_equal ["faccessat"], DeviceIntelligenceVerifier::Models.definitive_hooks(resolved)
  end

  def test_unknown_signal_falls_back_to_question_marks
    doc = JSON.parse('{"signals":[{"id":"INTEL_9999","severity":"CRITICAL"}]}')
    sig = DeviceIntelligenceVerifier::Signals.resolve(doc, reg, pol)[0]
    assert_equal "?", sig.detector
    assert_equal "?", sig.kind
    assert_equal "CRITICAL", sig.severity
  end

  def test_legacy_sig_prefix_bridges_to_intel
    doc = JSON.parse('{"signals":[{"id":"SIG_0052","severity":"CRITICAL"}]}')
    assert_equal "INTEL_0052", DeviceIntelligenceVerifier::Signals.resolve(doc, reg, pol)[0].id
  end
end
