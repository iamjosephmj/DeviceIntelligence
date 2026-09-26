# frozen_string_literal: true

require "openssl"
require "base64"

module DeviceIntelligenceVerifier
  # Loads the backend X25519 private half (ServerKey.kt port). Accepts PEM or
  # raw DER PKCS#8; a truncated tail-32 fallback mirrors the Kotlin no-XDH
  # path for exotic encodings.
  module ServerKey
    RAW_PKCS8_PREFIX = ["302e020100300506032b656e04220420"].pack("H*")

    module_function

    def from_pkcs8(der)
      begin
        return OpenSSL::PKey.read(der)
      rescue OpenSSL::PKey::PKeyError
        nil
      end
      raise ArgumentError, "PKCS#8 X25519 key too short: #{der.bytesize} bytes" if der.bytesize < 32
      der[-32..]  # the raw private scalar; X25519 math is done by X25519 (pure ruby)
    end

    def from_pem(pem)
      b64 = pem.gsub(/-----BEGIN [^-]*-----/, "")
               .gsub(/-----END [^-]*-----/, "")
               .gsub(/\s+/, "")
      from_pkcs8(Base64.decode64(b64))
    end

    def from_bytes(data)
      text = data.dup.force_encoding("ASCII-8BIT")
      text.include?("-----BEGIN") ? from_pem(text) : from_pkcs8(data)
    end

    def from_file(path)
      from_bytes(File.binread(path))
    end
  end
end
