# frozen_string_literal: true

require "openssl"

module DeviceIntelligenceVerifier
  module Attestation
  # The pinned Google hardware-attestation roots (PinnedRoots.kt port).
  # Bundled file: base64 DER, one root per line, '#' comments allowed.
  module PinnedRoots
    module_function

    def parse(text)
      text.split("\n").filter_map do |line|
        line = line.strip
        next if line.empty? || line.start_with?("#")
        OpenSSL::X509::Certificate.new(Base64.decode64(line))
      end
    end

    def default
      path = File.expand_path("../resources/pinned-roots.txt", __dir__)
      parse(File.read(path))
    end
  end
end
end
