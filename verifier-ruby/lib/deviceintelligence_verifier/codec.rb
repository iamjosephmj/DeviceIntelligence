# frozen_string_literal: true

require "json"

module DeviceIntelligenceVerifier
  # JSON round-trip for ScanSession (ScanSessionCodec.kt port). Decode grades a
  # truncated document DOWN to the suspicious value, never to the benign default
  # — a missing boolean always reads as the dangerous one.
  module ScanSessionCodec
    module_function

    def decode(json_text)
      o = JSON.parse(json_text)
      key = o["attestedKey"]
      raise ArgumentError, "session has no attestedKey" unless key.is_a?(String)
      ScanSession.new(
        attested_key: key,
        attested_app: o["attestedApp"] && AttestedApp.new(
          package_names: o["attestedApp"]["packageNames"] || [],
          signature_digests: o["attestedApp"]["signatureDigests"] || []),
        assurance: Assurance.const_get(o["assurance"].to_s),
        boot_state: o["bootState"] || "?",
        device_locked: o["deviceLocked"] == true,
        chain_trusted: o["chainTrusted"] == true,
        keybox_revoked: o["keyboxRevoked"] != false,
        cross_level_reuse: o["crossLevelReuse"] != false,
        device_prop_mismatch: o["devicePropMismatch"] != false,
        boot_state_spoofer: o["bootStateSpoofer"] != false,
        strongbox_chain_missing: o["strongboxChainMissing"] != false,
        software_attested: o["softwareAttested"] != false,
        os_patch_level: o["osPatchLevel"],
        vendor_patch_level: o["vendorPatchLevel"],
        boot_patch_level: o["bootPatchLevel"],
        fingerprint: o["fingerprint"] && DeviceFingerprint.new(
          id: o["fingerprint"]["id"], aid: o["fingerprint"]["aid"],
          security_level: o["fingerprint"]["securityLevel"],
          build: o["fingerprint"]["build"], kernel: o["fingerprint"]["kernel"],
          patch: o["fingerprint"]["patch"], installer: o["fingerprint"]["installer"]),
      )
    end

    def encode(s)
      fields = ["\"attestedKey\":#{JSON.generate(s.attested_key)}"]
      if s.attested_app.nil?
        fields << '"attestedApp":null'
      else
        fields << "\"attestedApp\":{\"packageNames\":#{JSON.generate(s.attested_app.package_names)},"
        fields.last << "\"signatureDigests\":#{JSON.generate(s.attested_app.signature_digests)}}"
      end
      fields << "\"assurance\":\"#{s.assurance}\""
      fields << "\"bootState\":#{JSON.generate(s.boot_state)}"
      fields << "\"deviceLocked\":#{s.device_locked}"
      fields << "\"chainTrusted\":#{s.chain_trusted}"
      fields << "\"keyboxRevoked\":#{s.keybox_revoked}"
      fields << "\"crossLevelReuse\":#{s.cross_level_reuse}"
      fields << "\"devicePropMismatch\":#{s.device_prop_mismatch}"
      fields << "\"bootStateSpoofer\":#{s.boot_state_spoofer}"
      fields << "\"strongboxChainMissing\":#{s.strongbox_chain_missing}"
      fields << "\"softwareAttested\":#{s.software_attested}"
      fields << "\"osPatchLevel\":#{json_or_null(s.os_patch_level)}"
      fields << "\"vendorPatchLevel\":#{json_or_null(s.vendor_patch_level)}"
      fields << "\"bootPatchLevel\":#{json_or_null(s.boot_patch_level)}"
      if s.fingerprint.nil?
        fields << '"fingerprint":null'
      else
        fp = s.fingerprint
        pairs = %w[id aid securityLevel build kernel patch installer].map do |k|
          "#{JSON.generate(k)}:#{json_or_null(fp.send(snake(k)))}"
        end
        fields << "\"fingerprint\":{#{pairs.join(',')}}"
      end
        "{#{fields.join(',')}}"
    end

    def json_or_null(v)
      v.nil? ? "null" : JSON.generate(v)
    end

    def snake(name)
      name.gsub(/([A-Z]+)/) { "_#{Regexp.last_match(1).downcase }" }
    end
  end
end
