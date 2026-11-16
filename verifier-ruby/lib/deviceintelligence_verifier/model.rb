# frozen_string_literal: true

module DeviceIntelligenceVerifier
  # Wire-string constants: the decision rides the token as these exact tokens.
  module Decision
    TRUSTWORTHY = "TRUSTWORTHY"
    COMPROMISED = "COMPROMISED"
    REJECT = "REJECT"
  end

  module CheckKind
    AUTH = "AUTH"
    INTEGRITY = "INTEGRITY"
  end

  module Assurance
    SOFTWARE = "SOFTWARE"
    TEE = "TEE"
    STRONGBOX = "STRONGBOX"
  end

  Check = Struct.new(:name, :ok, :detail, :kind, keyword_init: true)
  DeviceInfo = Struct.new(:api, :abi, :model, keyword_init: true)
  AttestedApp = Struct.new(:package_names, :signature_digests, keyword_init: true)
  DeviceFingerprint = Struct.new(:id, :aid, :security_level, :build, :kernel, :patch,
                                 :installer, keyword_init: true)

  # One resolved signal: the opaque INTEL_ code plus the registry metadata and
  # the policy verdict. Only `id`, `severity`, `detail` come from the device.
  ResolvedSignal = Struct.new(:id, :detector, :kind, :title, :severity, :detail,
                              :blocking, :attributes, keyword_init: true) do
    def attributes
      self[:attributes] || {}
    end

    # Enrichment accessors — the correlation layer reads these, not raw attrs.
    %w[path module_id needed links_hook_lib hooked_symbol hooked_by
       hook_stub_regions].each do |key|
      define_method(key) { attributes[key] }
    end

    def linked_libraries
      (attributes["needed"] || "").split(",").map(&:strip).reject(&:empty?)
    end
  end

  ScanSession = Struct.new(:attested_key, :attested_app, :assurance, :boot_state,
                           :device_locked, :chain_trusted, :keybox_revoked,
                           :cross_level_reuse, :device_prop_mismatch,
                           :boot_state_spoofer, :strongbox_chain_missing,
                           :software_attested, :os_patch_level, :vendor_patch_level,
                           :boot_patch_level, :fingerprint, keyword_init: true)

  # The HMAC-carried session facts a steady-state scan proves possession of.
  Session = Struct.new(:pinned_key_spki_hex, :assurance, :boot_state,
                       :device_locked, :issued_at, :chain_trusted,
                       :keybox_revoked, :cross_level_reuse,
                       :strongbox_chain_missing, :device_prop_mismatch,
                       :boot_state_spoofer, :software_attested, keyword_init: true)

  DecodedToken = Struct.new(:schema_version, :point, :ts, :nonce, :device,
                            :signals, :has_binding, keyword_init: true)

  # The layered verdict. `decision` is the authority;
  #   REJECT       — authenticity failed (not a genuine, fresh binding)
  #   COMPROMISED  — genuine, but the device (or a signal) is compromised
  #   TRUSTWORTHY  — all three layers cleared
  VerificationResult = Struct.new(:decision, :authentic, :device_integrity_ok,
                                  :checks, :schema_version, :point, :ts, :nonce,
                                  :device, :signals, keyword_init: true) do
    def blocking_signals
      signals.select(&:blocking)
    end
  end
end
