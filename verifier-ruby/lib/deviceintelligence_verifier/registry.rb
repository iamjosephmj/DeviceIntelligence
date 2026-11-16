# frozen_string_literal: true

require "json"

module DeviceIntelligenceVerifier
  SignalMeta = Struct.new(:id, :detector, :kind, :severity, :title, keyword_init: true)

  # The signal taxonomy: opaque INTEL_ codes resolved to their meaning. The
  # device never ships detector/kind — only the backend holds the table, so a
  # code is meaningful only against THIS registry.
  class SignalRegistry
    attr_reader :size

    def initialize(by_id)
      @by_id = by_id
      @size = by_id.size
    end

    def self.from_json(text)
      root = JSON.parse(text)
      by_id = {}
      (root["signals"] || []).each do |row|
        next if row["status"] == "retired"
        by_id[row["id"]] = SignalMeta.new(
          id: row["id"],
          detector: row["detector"] || "?",
          kind: row["kind"] || "?",
          severity: row["severity"] || "",
          title: row["title"] || "",
        )
      end
      new(by_id)
    end

    def self.bundled
      path = File.expand_path("resources/signals-registry.json", __dir__)
      from_json(File.read(path))
    end

    # Nil-safe: unknown codes, nil, anything — nil back.
    def get(id)
      id && @by_id[id] || nil
    end
    alias [] get
  end
end
