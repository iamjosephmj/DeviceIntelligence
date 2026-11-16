# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

# RFC 5869 known-answer tests.
class HkdfTest < Minitest::Test
  IKM22 = ["0b" * 22].pack("H*")

  def test_rfc5869_case1_with_salt_and_info
    okm = DeviceIntelligenceVerifier::Hkdf.sha256(
      IKM22, ["000102030405060708090a0b0c"].pack("H*"),
      ["f0f1f2f3f4f5f6f7f8f9"].pack("H*"), 42)
    assert_equal "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" \
                 "34007208d5b887185865", okm.unpack1("H*")
  end

  def test_rfc5869_case3_empty_salt_and_info
    okm = DeviceIntelligenceVerifier::Hkdf.sha256(IKM22, "", "", 42)
    assert_equal "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" \
                 "9d201395faa4b61a96c8", okm.unpack1("H*")
  end

  def test_rejects_output_over_255_blocks
    assert_raises(RangeError) do
      DeviceIntelligenceVerifier::Hkdf.sha256("\x01", "", "", 255 * 32 + 1)
    end
  end

  def test_token_derivation_shape_is_32_bytes
    key = DeviceIntelligenceVerifier::Hkdf.sha256(
      ["00" * 32].pack("H*"), ["10" * 12].pack("H*"),
      "intel-token-v2\x00", 32)
    assert_equal 32, key.bytesize
  end
end
