# frozen_string_literal: true

# DeviceIntelligence backend token verifier (Ruby port of the Kotlin/JVM
# verifier). Packaged by feature, mirroring the kotlin/python/node layouts;
# this facade keeps the flat public surface:
#
#   require "deviceintelligence_verifier"
#   result = DeviceIntelligenceVerifier::TokenVerifier.new.verify(token, nonce)

require_relative "deviceintelligence_verifier/model"
require_relative "deviceintelligence_verifier/keystream"
require_relative "deviceintelligence_verifier/hkdf"
require_relative "deviceintelligence_verifier/registry"
require_relative "deviceintelligence_verifier/policy"
require_relative "deviceintelligence_verifier/signals"
require_relative "deviceintelligence_verifier/lab_keys"
require_relative "deviceintelligence_verifier/x25519"
require_relative "deviceintelligence_verifier/token_crypto"
require_relative "deviceintelligence_verifier/session_signer"
require_relative "deviceintelligence_verifier/server_key"
require_relative "deviceintelligence_verifier/pinned_roots"
require_relative "deviceintelligence_verifier/chain_verifier"
require_relative "deviceintelligence_verifier/crl"
require_relative "deviceintelligence_verifier/attestation"
require_relative "deviceintelligence_verifier/token_decoder"
require_relative "deviceintelligence_verifier/token_verifier"
require_relative "deviceintelligence_verifier/codec"

module DeviceIntelligenceVerifier
  class Error < StandardError; end
end
