# frozen_string_literal: true

module DeviceIntelligenceVerifier
  # Server-side policy — the false-positive tuning that lives OFF the device.
  class Policy
    attr_accessor :block_severities, :allow, :block, :require_strong_box,
                  :max_patch_age_days, :observe_unconfirmed_rwx

    def initialize(block_severities: %w[CRITICAL], allow: [], block: [],
                   require_strong_box: false, max_patch_age_days: 365,
                   observe_unconfirmed_rwx: false)
      @block_severities = block_severities
      @allow = allow
      @block = block
      @require_strong_box = require_strong_box
      @max_patch_age_days = max_patch_age_days
      @observe_unconfirmed_rwx = observe_unconfirmed_rwx
    end

    # The single blocking decision. Order is normative:
    #   1. allow-list wins over everything
    #   2. block-list wins over severity
    #   3. a CONFIRMED RWX hook pool always blocks
    #   4. opting into observe-unconfirmed-RWX downgrades a BARE RWX finding
    #   5. otherwise the severity table decides
    def is_blocking(sid = nil, severity = nil, kind: nil, hook_stub_regions: nil)
      return false if sid && allow.include?(sid)
      return true if sid && block.include?(sid)
      if kind == "rwx_memory_mapping"
        return true if (hook_stub_regions || 0) > 0
        return false if observe_unconfirmed_rwx
      end
      block_severities.include?((severity || "").upcase)
    end
  end
end
