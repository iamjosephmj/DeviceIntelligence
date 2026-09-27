# frozen_string_literal: true

# DeviceIntelligence backend token verifier (Ruby port of the Kotlin/JVM
# verifier). Packaged by feature, mirroring the kotlin/python/node layouts;
# this facade keeps the flat public surface:
#
#   require "deviceintelligence_verifier"
#   result = DeviceIntelligenceVerifier::TokenVerifier.new.verify(token, nonce)


module DeviceIntelligenceVerifier
  class Error < StandardError; end
end
require_relative "deviceintelligence_verifier/model"
require_relative "deviceintelligence_verifier/tokens/keystream"
require_relative "deviceintelligence_verifier/attestation/hkdf"
require_relative "deviceintelligence_verifier/tokens/lab_keys"
require_relative "deviceintelligence_verifier/registry"
require_relative "deviceintelligence_verifier/policy"
require_relative "deviceintelligence_verifier/tokens/signals"
require_relative "deviceintelligence_verifier/tokens/token_crypto"
require_relative "deviceintelligence_verifier/tokens/session_signer"
require_relative "deviceintelligence_verifier/tokens/server_key"
require_relative "deviceintelligence_verifier/attestation/pinned_roots"
require_relative "deviceintelligence_verifier/attestation/chain_verifier"
require_relative "deviceintelligence_verifier/attestation/crl"
require_relative "deviceintelligence_verifier/attestation/attestation"
require_relative "deviceintelligence_verifier/tokens/token_decoder"
require_relative "deviceintelligence_verifier/tokens/token_verifier"
require_relative "deviceintelligence_verifier/codec"

# Flat public surface: the feature modules stay importable directly
# (DeviceIntelligenceVerifier::Tokens::TokenVerifier, ...::Attestation::Attestation).
module DeviceIntelligenceVerifier
  TokenVerifier = Tokens::TokenVerifier
  TokenDecoder = Tokens::TokenDecoder
  SessionSigner = Tokens::SessionSigner
  TokenCryptoV2 = Tokens::TokenCryptoV2
  Signals = Tokens::Signals
  Hkdf = Attestation::Hkdf
  AttestationCrl = Attestation::AttestationCrl
end
