# frozen_string_literal: true

module DeviceIntelligenceVerifier
  module Attestation
  # Attestation-key revocation list (the weekly-baked encrypted crl.bin asset,
  # already decrypted by the caller). Serial matching normalizes case, an
  # optional 0x prefix, and leading zeros away — "0" stays "0".
  class AttestationCrl
    def self.normalize(serial_hex)
      s = serial_hex.strip.downcase.sub(/\A0x/, "").sub(/\A0+/, "")
      s.empty? ? "0" : s
    end

    def self.parse(text)
      revoked = text.split("\n").filter_map do |line|
        n = normalize(line.split("#").first.to_s)
        n.empty? ? nil : n
      end
      new(revoked.to_set)
    end

    def self.from_file(path)
      parse(File.read(path))
    end

    def initialize(revoked)
      @revoked = revoked
    end

    def revoked?(serial_hex)
      @revoked.include?(self.class.normalize(serial_hex))
    end

    def revoked_cert?(cert)
      revoked?(cert.serial.to_s(16))
    end

    def first_revoked(*chains)
      chains.flatten.each do |cert|
        h = self.class.normalize(cert.serial.to_s(16))
        return h if @revoked.include?(h)
      end
      nil
    end

    def size
      @revoked.size
    end
  end
end

require "set"
end
