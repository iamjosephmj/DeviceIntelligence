# frozen_string_literal: true

require "openssl"
require_relative "x25519"

module DeviceIntelligenceVerifier
  # v2 ECIES token crypto (TokenCryptoV2.kt port) + the v1 discriminator.
  # Wire: "2:" + hex(version || epoch || eph_pub(32) || nonce(12) || ct || tag).
  # Every corruption fails the GCM tag — a tampered token never decrypts.
  module TokenCryptoV2
    PREFIX = "2:"
    INFO_PREFIX = "intel-token-v2"
    HEADER = 1 + 1 + 32 + 12
    TAG = 16

    module_function

    # A v1 token is pure lowercase hex (no ":"); v2 carries the "2:" prefix.
    def is_v2(token)
      token.start_with?(PREFIX)
    end

    # Decrypt a "2:" token. [server_priv] is the 32-byte X25519 private scalar
    # (or an OpenSSL::PKey::X25519 carrying one). Raises on tamper (GCM auth),
    # malformed input, and unparseable keys — never returns plaintext on any
    # corruption.
    def decrypt(token_v2, server_priv)
      scalar = if server_priv.respond_to?(:private_key)
                 server_priv.private_key
               else
                 server_priv
               end
      raise ArgumentError, "server private scalar must be 32 bytes" unless
        scalar.is_a?(String) && scalar.bytesize == 32

      raise ArgumentError, "not a v2 token" unless token_v2.start_with?(PREFIX)
      body = token_v2[PREFIX.length..]
      raise ArgumentError, "odd-length hex" if body.length.odd?
      raise ArgumentError, "bad hex char" unless body.match?(/\A[0-9a-fA-F]*\z/)
      p = [body].pack("H*")
      raise ArgumentError, "v2 token too short" if p.bytesize < HEADER + TAG

      bytes = p.bytes
      version = bytes[0]
      epoch = bytes[1]
      eph_pub = bytes[2, 32].pack("C*")
      nonce = bytes[34, 12].pack("C*")
      ct_and_tag = p.byteslice(HEADER..) || "".b

      eph = eph_pub.dup
      eph.setbyte(31, eph.getbyte(31) & 0x7F) # RFC 7748: the ignored high bit
      shared = X25519.shared_secret(scalar, eph)
      key = Hkdf.sha256(shared, nonce, INFO_PREFIX + epoch.chr, 32)

      aad = [version, epoch].pack("C*") + eph_pub
      ct = ct_and_tag.byteslice(0, ct_and_tag.bytesize - TAG)
      tag = ct_and_tag.byteslice(ct_and_tag.bytesize - TAG, TAG)

      d = OpenSSL::Cipher.new("aes-256-gcm").decrypt
      d.key = key
      d.iv = nonce
      d.auth_data = aad
      d.auth_tag = tag
      d.update(ct) + d.final
    end
  end
end
