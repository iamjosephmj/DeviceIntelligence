# frozen_string_literal: true

require "openssl"

module DeviceIntelligenceVerifier
  module Attestation
  # Android Key Attestation extension reader (Attestation.kt port), on
  # OpenSSL::ASN1. KeyDescription element indexes (spec §8):
  #   [1] attestationSecurityLevel (ENUMERATED)
  #   [4] attestationChallenge (OCTET STRING)
  #   [6] softwareEnforced AuthorizationList (SEQUENCE)
  #   [7] teeEnforced AuthorizationList (SEQUENCE) — preferred over [6]
  # AuthorizationList entries are context-tagged [704]=BF 85 40 (RootOfTrust),
  # [709]=BF 85 45 (attestationApplicationId), [705/706/718/719] patch levels.
  module Attestation
    OID = "1.3.6.1.4.1.11129.2.1.17"
    ROOT_OF_TRUST_TAG = [0xBF, 0x85, 0x40].pack("C*")

    AttestationFields = Struct.new(:security_level, :verified_boot_state,
                                   :device_locked, keyword_init: true)

    SECURITY_LEVEL_NAMES = { 0 => "Software", 1 => "TrustedEnvironment", 2 => "StrongBox" }.freeze
    BOOT_STATE_NAMES = { 0 => "Verified", 1 => "SelfSigned", 2 => "Unverified", 3 => "Failed" }.freeze

    module_function

    def security_level_name(level)
      return "?" if level.nil?
      SECURITY_LEVEL_NAMES[level] || level.to_s
    end

    def boot_state_name(state)
      return "?" if state.nil?
      BOOT_STATE_NAMES[state] || state.to_s
    end

    # The KeyDescription DER: the extnValue OCTET STRING payload of our OID.
    # Extension#value renders unknown extensions as a human-readable string, so
    # re-decode the extension DER and take the inner OCTET STRING directly.
    def key_description_der(cert)
      ext = cert.extensions.find { |e| e.oid == OID }
      raise ArgumentError, "no Android attestation extension on leaf" unless ext
      seq = OpenSSL::ASN1.decode(ext.to_der)
      octet = seq.value[1]
      raise ArgumentError, "attestation extension has no value" unless octet
      octet.value
    end

    def key_description_elements(cert)
      decoded = OpenSSL::ASN1.decode(key_description_der(cert))
      raise ArgumentError, "attestation extension is not a SEQUENCE" unless
        decoded.tag_class == :UNIVERSAL && decoded.tag == 16
      decoded.value
    end

    def challenge(cert)
      elems = key_description_elements(cert)
      raise ArgumentError, "KeyDescription too short" if elems.size <= 4
      elems[4].value
    end

    def fields(cert)
      elems = key_description_elements(cert)
      security_level = asn1_int(elems[1]) if elems.size > 1

      locked = nil
      boot_state = nil
      # teeEnforced [7] preferred over softwareEnforced [6]; both are plain
      # SEQUENCEs whose entries carry the context tags.
      [7, 6].each do |idx|
        next if elems.size <= idx
        entries(elems[idx]).each do |entry|
          next unless entry.tag_bytes == ROOT_OF_TRUST_TAG
          rot = entry.value
          locked = asn1_bool(rot[1]) if rot.size > 1
          boot_state = asn1_int(rot[2]) if rot.size > 2
          break
        end
        break unless boot_state.nil?
      end

      AttestationFields.new(security_level: security_level,
                            verified_boot_state: boot_state,
                            device_locked: locked)
    end

    # The context-tagged entries of an AuthorizationList SEQUENCE.
    def entries(seq)
      seq.value
    rescue NoMethodError
      []
    end

    def asn1_int(asn1)
      v = asn1.value
      v.is_a?(Integer) ? v : (v.empty? ? nil : v.unpack1("C"))
    rescue NoMethodError, TypeError
      nil
    end

    def asn1_bool(asn1)
      v = asn1.value
      v == true || (v.is_a?(String) && !v.empty? && v.unpack1("C") != 0)
    rescue NoMethodError
      nil
    end
  end
end
end
