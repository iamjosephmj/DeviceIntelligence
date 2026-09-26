# frozen_string_literal: true

require "digest"

module DeviceIntelligenceVerifier
  # v1 symmetric token crypto (Keystream.kt port). Confidentiality in transit
  # only — the scan path REJECTS v1 tokens; this exists to decode legacy ones.
  module Keystream
    PHRASE = "intel-verdict-token-key-v1" # WIRE-CONSTANT (do NOT rebrand)

    module_function

    def decrypt_bytes(cipher)
      key = Digest::SHA256.digest(PHRASE)
      out = cipher.bytes
      block = 0
      off = 0
      while off < out.size
        ks = Digest::SHA256.digest(key + [block].pack("V"))
        take = [32, out.size - off].min
        take.times { |i| out[off + i] ^= ks[i].ord }
        off += 32
        block += 1
      end
      out.pack("C*")
    end

    def decrypt_hex(token_hex)
      decrypt_bytes([token_hex.strip].pack("H*")).force_encoding("UTF-8")
    end
  end
end
