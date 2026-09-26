# frozen_string_literal: true

require "openssl"
require "base64"
require "json"

module DeviceIntelligenceVerifier
  # Stateless HMAC-signed session tokens (SessionSigner.kt port). The token is
  # "<payload-b64url>.<mac-b64url>"; tampering with either half fails verification.
  class SessionSigner
    DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60

    attr_reader :max_age_seconds

    def initialize(server_key, max_age_seconds: DEFAULT_MAX_AGE_SECONDS, now: nil)
      @key = server_key
      @max_age_seconds = max_age_seconds
      @now = now || -> { Time.now.to_i }
    end

    def issue(session)
      payload = JSON.generate(
        "pinnedKey" => session.pinned_key_spki_hex,
        "assurance" => session.assurance,
        "boot" => session.boot_state,
        "locked" => session.device_locked,
        "issuedAt" => session.issued_at,
        "chainTrusted" => session.chain_trusted,
        "kbRevoked" => session.keybox_revoked,
        "xlReuse" => session.cross_level_reuse,
        "sbMissing" => session.strongbox_chain_missing,
        "propMismatch" => session.device_prop_mismatch,
        "bootSpoofer" => session.boot_state_spoofer,
        "swAttest" => session.software_attested,
      )
      "#{encode(payload)}.#{encode(mac(payload))}"
    end

    def open(session_id)
      dot = session_id.index(".")
      return nil if dot.nil?
      payload = decode(session_id[0, dot])
      mac_bytes = decode(session_id[(dot + 1)..])
      return nil if payload.nil? || mac_bytes.nil?
      return nil unless secure_compare(mac(payload), mac_bytes)

      o = JSON.parse(payload)
      issued_at = o["issuedAt"]
      return nil unless issued_at.is_a?(Numeric) && issued_at.positive?
      return nil if @now.call - issued_at > @max_age_seconds

      Session.new(
        pinned_key_spki_hex: o["pinnedKey"],
        assurance: o["assurance"],
        boot_state: o["boot"],
        device_locked: o["locked"] == true,
        issued_at: issued_at,
        chain_trusted: o["chainTrusted"] == true,
        keybox_revoked: o["kbRevoked"] == true,
        cross_level_reuse: o["xlReuse"] == true,
        strongbox_chain_missing: o["sbMissing"] == true,
        device_prop_mismatch: o["propMismatch"] == true,
        boot_state_spoofer: o["bootSpoofer"] == true,
        software_attested: o["swAttest"] == true,
      )
    rescue JSON::ParserError, TypeError
      nil
    end

    private

    def mac(data)
      OpenSSL::HMAC.digest("SHA256", @key, data)
    end

    def encode(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end

    def decode(str)
      Base64.urlsafe_decode64(str)
    rescue ArgumentError
      nil
    end

    # Constant-time comparison (timing-safe equality, as timingSafeEqual is elsewhere).
    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize
      diff = 0
      a.bytes.zip(b.bytes) { |x, y| diff |= x ^ y }
      diff.zero?
    end
  end
end
