# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

# RFC 7748 known-answer tests — validating the pure-Ruby X25519 that the v2
# envelope depends on.
class X25519KatTest < Minitest::Test
  V1_K = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
  V1_U = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
  V1_O = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
  V2_K = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
  V2_U = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
  V2_O = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
  DH_A = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  DH_B = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  def mult(k_hex, u_hex)
    DeviceIntelligenceVerifier::X25519.shared_secret(
      [k_hex].pack("H*"), [u_hex].pack("H*")).unpack1("H*")
  end

  def test_rfc7748_vector1
    assert_equal V1_O, mult(V1_K, V1_U)
  end

  def test_rfc7748_vector2
    assert_equal V2_O, mult(V2_K, V2_U)
  end

  def test_diffie_hellman_agrees
    a_pub = DeviceIntelligenceVerifier::X25519.public_from_private(
      [DH_A].pack("H*")).unpack1("H*")
    b_pub = DeviceIntelligenceVerifier::X25519.public_from_private(
      [DH_B].pack("H*")).unpack1("H*")
    assert_equal "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", a_pub
    assert_equal "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pub
    assert_equal SHARED, mult(DH_A, b_pub)
    assert_equal SHARED, mult(DH_B, a_pub)
  end

  def test_decodes_u_with_the_high_bit_masked
    # The last byte's high bit is ignored per RFC 7748: u | (1<<255) == u.
    u = ["e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"].pack("H*")
    masked = u.dup
    masked.setbyte(31, masked.getbyte(31) | 0x80)
    assert_equal mult(V1_K, u.unpack1("H*")),
                 DeviceIntelligenceVerifier::X25519.shared_secret(
                   [V1_K].pack("H*"), masked).unpack1("H*")
  end
end
