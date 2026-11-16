# frozen_string_literal: true

module DeviceIntelligenceVerifier
  module Tokens
  # Signal resolution: turn the device's opaque findings into registry-backed
  # ResolvedSignals, and correlate structural + behavioral hook evidence.
  module Signals
    # The detail tokens a backend may enrich with (space-separated k=v pairs).
    ATTR_KEYS = %w[path module_id needed links_hook_lib hooked_symbol hooked_by
                   target ondisk_confirmed on_disk_prologue trampoline_class
                   object base seals key get area hook_stub_regions
                   region_count].freeze

    def self.parse_attrs(detail)
      attrs = {}
      return attrs if detail.nil? || detail.empty?
      detail.split(" ").each do |tok|
        eq = tok.index("=")
        next unless eq && eq > 0
        k = tok[0, eq]
        attrs[k] = tok[(eq + 1)..] if ATTR_KEYS.include?(k)
      end
      attrs
    end

    def self.resolve(doc, registry, policy)
      (doc["signals"] || []).map do |s|
        raw_id = s["id"] || "INTEL_UNKNOWN"
        # Legacy SIG_-prefixed ids normalize before lookup.
        id = raw_id.start_with?("SIG_") ? "INTEL_#{raw_id[4..]}" : raw_id
        meta = registry.get(id)
        severity = s["severity"] || (meta && meta.severity) || ""
        detail = s["detail"] || ""
        attrs = parse_attrs(detail)
        stubs = attrs["hook_stub_regions"]&.to_i
        ResolvedSignal.new(
          id: id, detector: meta ? meta.detector : "?", kind: meta ? meta.kind : "?",
          title: meta ? meta.title : "", severity: severity, detail: detail,
          blocking: policy.is_blocking(id, severity, kind: meta && meta.kind,
                                       hook_stub_regions: stubs),
          attributes: attrs,
        )
      end
    end

    def self.device(doc)
      d = doc["device"]
      return nil unless d
      DeviceInfo.new(
        api: d["api"].is_a?(Numeric) ? d["api"] : nil,
        abi: d["abi"] || nil,
        model: d["model"] || nil,
      )
    end
    # Definitive hook = the SAME symbol seen both structurally (inline hook /
    # stub) and behaviorally (syscall divergence). Sorted for determinism.
    def self.definitive_hooks(signals)
      structural = signals.select { |s| s.kind == "libc_inline_hook" || s.kind == "libc_inline_stub" }
                          .filter_map { |s| s.attributes["hooked_symbol"] }.to_set
      behavioral = signals.select { |s| s.kind == "syscall_divergence" }
                          .filter_map { |s| s.attributes["hooked_symbol"] }.to_set
      (structural & behavioral).sort
    end
  end
end

require "set"
end
