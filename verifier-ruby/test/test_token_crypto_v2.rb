# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

# The v2 ECIES contract: the native-interop KAT, the tamper matrix, malformed input.
class TokenCryptoV2Test < Minitest::Test
  SERVER_PRIV_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  TOKEN = "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d10111213" \
          "1415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a" \
          "2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b"
  EMPTY_TOKEN = "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d1011" \
                "12131415161718191a1b9a7f7296f43354e241400ee7b8946c46"
  EXPECTED = "signed_content\n--BINDING\nSIG...\nCERT..."

  def server_priv
    [SERVER_PRIV_HEX].pack("H*")  # the raw 32-byte X25519 scalar
  end

  def flip_at(token, i)
    body = token[2..].chars
    body[i] = body[i] == "0" ? "1" : "0"
    "2:" + body.join
  end

  def test_decrypts_native_v2_token
    out = DeviceIntelligenceVerifier::TokenCryptoV2.decrypt(TOKEN, server_priv)
    assert_equal EXPECTED, out.force_encoding("UTF-8")
  end

  def test_decrypts_empty_ciphertext_token
    out = DeviceIntelligenceVerifier::TokenCryptoV2.decrypt(EMPTY_TOKEN, server_priv)
    assert_empty out
  end

  def test_tamper_fails
    [0, 2, 10, 70, 92].each do |i|
      assert_raises(StandardError) do
        DeviceIntelligenceVerifier::TokenCryptoV2.decrypt(flip_at(TOKEN, i), server_priv)
      end
    end
  end

  def test_tamper_tag_fails
    assert_raises(StandardError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt(
        flip_at(TOKEN, TOKEN.length - 3), server_priv)
    end
  end

  def test_wrong_server_key_fails
    other = "0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"
    assert_raises(StandardError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt(TOKEN, [other].pack("H*"))
    end
  end

  def test_all_zero_ephemeral_point_throws
    body = TOKEN[2..].chars
    (4...68).each { |i| body[i] = "0" }
    assert_raises(StandardError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt("2:" + body.join, server_priv)
    end
  end

  def test_rejects_missing_prefix
    assert_raises(ArgumentError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt("deadbeefcafe", server_priv)
    end
  end

  def test_rejects_too_short_payload
    assert_raises(ArgumentError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt("2:0203", server_priv)
    end
  end

  def test_rejects_odd_length_hex
    assert_raises(ArgumentError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt("2:abc", server_priv)
    end
  end

  def test_rejects_non_hex_chars
    assert_raises(ArgumentError) do
      DeviceIntelligenceVerifier::TokenCryptoV2.decrypt("2:zzzz", server_priv)
    end
  end

  def test_is_v2_discriminates_from_v1
    v2 = DeviceIntelligenceVerifier::TokenCryptoV2
    assert v2.is_v2(TOKEN)
    refute v2.is_v2("deadbeefcafe")
    refute v2.is_v2("")
    refute v2.is_v2("2")
  end
end
