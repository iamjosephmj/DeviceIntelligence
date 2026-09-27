# frozen_string_literal: true

require "openssl"
require "digest"

module DeviceIntelligenceVerifier
  module Attestation
  # Token attestation chain validation (ChainVerifier.kt port). Signature-only:
  # each cert must be signed by the next, and the chain top must terminate in a
  # pinned Google root (by SHA-256 of the DER, or by key verification — Pixel
  # chains mix EC keyboxes with RSA Google intermediates).
  module ChainVerifier
    module_function

    def parse_chain(certs_hex)
      certs_hex.map { |h| OpenSSL::X509::Certificate.new([h].pack("H*")) }
    end

    def sha256_fp(cert)
      Digest::SHA256.digest(cert.to_der)
    end

    # Returns the pinned root the chain terminates in, or raises.
    def verify_to_pinned_root(chain, pinned_roots)
      raise ArgumentError, "empty chain" if chain.empty?
      chain.each_cons(2) { |cert, issuer| verify_signed_by(cert, issuer) }
      top = chain.last
      top_fp = sha256_fp(top)
      pinned_roots.each do |root|
        return root if top_fp == sha256_fp(root)
        begin
          verify_signed_by(top, root)
          return root
        rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError
          next
        end
      end
      raise ArgumentError, "chain top does not chain to a pinned Google root"
    end

    def verify_signed_by(cert, issuer)
      raise OpenSSL::PKey::PKeyError, "signature mismatch" unless cert.verify(issuer.public_key)
    end
  end
end
end
