# frozen_string_literal: true

module DeviceIntelligenceVerifier
  module Tokens
  # Fixed lab HMAC key for stateless session tokens — shared by every port.
  module LabKeys
    SERVER_KEY = "intel-lab-session-key-v1"
  end
end
end
