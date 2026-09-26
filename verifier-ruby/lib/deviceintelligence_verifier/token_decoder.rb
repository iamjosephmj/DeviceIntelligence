# frozen_string_literal: true

require "json"

module DeviceIntelligenceVerifier
  # Decrypts a token and returns its document WITHOUT verifying
  # (TokenDecoder.kt port).
  class TokenDecoder
    BINDING_SEP = "\n--BINDING\n"

    DecodedToken = Struct.new(:schema_version, :point, :ts, :nonce, :device,
                              :signals, :has_binding, keyword_init: true)

    def initialize(registry: nil, policy: nil)
      @registry = registry || SignalRegistry.bundled
      @policy = policy || Policy.new
    end

    def decode(token_hex)
      text = Keystream.decrypt_hex(token_hex)
      idx = text.index(BINDING_SEP)
      signed = idx ? text[0, idx] : text
      doc = JSON.parse(signed)
      DecodedToken.new(
        schema_version: doc["schemaVersion"], point: doc["point"], ts: doc["ts"],
        nonce: doc["nonce"], device: Signals.device(doc),
        signals: Signals.resolve(doc, @registry, @policy),
        has_binding: !idx.nil?,
      )
    end
  end
end
