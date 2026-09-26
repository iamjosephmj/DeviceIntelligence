# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

# Offline parity against a REAL token captured from the rooted Pixel 6 Pro
# (KernelSU + TrickyStore). The Ruby verifier must grade this exact token+nonce
# COMPROMISED, identically to the Kotlin reference (and the python/node ports).
class PixelParityTest < Minitest::Test
  FIXTURES = File.expand_path("../../verifiers/fixtures", __dir__)

  def test_pixel_real_token_parity_compromised
    token = File.read(File.join(FIXTURES, "pixel-token.hex")).strip
    nonce = File.read(File.join(FIXTURES, "pixel-nonce.hex")).strip
    res = DeviceIntelligenceVerifier::TokenVerifier.new.verify(token, nonce)

    assert res.authentic
    refute res.device_integrity_ok
    assert_equal "COMPROMISED", res.decision

    # The token is a registryVersion-1 capture: its attestation signal carries
    # the pre-reshuffle code, which the v2 table resolves to whatever row owns
    # that number today. A fresh device capture re-establishes attribution.
    sig0 = res.signals.find { |s| s.id == "INTEL_0000" }
    refute_nil sig0
    assert sig0.blocking

    checks = res.checks.to_h { |c| [c.name, c.ok] }
    assert checks["binding present"]
    assert checks["nonce matches issued"]
    assert checks["chain -> pinned Google root"]
    assert checks["signature over verdict"]
    refute checks["verified boot state = Verified"]
  end
end
