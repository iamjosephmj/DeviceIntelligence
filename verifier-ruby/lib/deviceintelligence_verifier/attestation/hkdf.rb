# frozen_string_literal: true

require "openssl"

module DeviceIntelligenceVerifier
  module Attestation
  # HKDF-SHA256 (RFC 5869). Ruby's OpenSSL bindings implement the extract-and-
  # expand directly; the guard mirrors the spec's 255-block output ceiling.
  module Hkdf
    MAX_OUT = 255 * 32

    module_function

    def sha256(ikm, salt, info, length)
      raise RangeError, "HKDF outLen out of range: #{length}" if length.negative? || length > MAX_OUT
      salt = "\x00".b * 32 if salt.empty?
      OpenSSL::KDF.hkdf(ikm, salt: salt, info: info, length: length, hash: "SHA256")
    end
  end
end
end
