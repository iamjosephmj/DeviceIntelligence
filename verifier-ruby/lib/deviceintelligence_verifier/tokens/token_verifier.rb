# frozen_string_literal: true

require "openssl"

module DeviceIntelligenceVerifier
  module Tokens
  # The v1-era verify flow (TokenVerifier.kt port): authenticity + TEE facts.
  # Layered like every port: AUTH failures => REJECT, INTEGRITY failures =>
  # COMPROMISED, blocking signals => COMPROMISED, else TRUSTWORTHY.
  class TokenVerifier
    BINDING_SEP = "\n--BINDING\n"
    FS = "\x1F"

    def initialize(registry: nil, policy: nil, pinned_roots: nil)
      @registry = registry || SignalRegistry.bundled
      @policy = policy || Policy.new
      @pinned_roots = pinned_roots || Attestation::PinnedRoots.default
    end

    def verify(token_hex, issued_nonce)
      checks = Checks.new

      text = Keystream.decrypt_hex(token_hex)
      sep = text.index(BINDING_SEP)
      signed = sep ? text[0, sep] : text
      binding = sep ? text[(sep + BINDING_SEP.length)..] : ""
      doc = safe { JSON.parse(signed) } || {}

      return result(checks, doc) unless checks.auth(
        "binding present", !sep.nil?, sep.nil? ? "unbound/legacy token" : "")
      unless doc.is_a?(Hash) && !doc.empty?
        checks.auth("signed content is JSON", false, "unparseable signed_content")
        return result(checks, doc)
      end

      token_nonce = doc["nonce"] || ""
      checks.auth("nonce matches issued", token_nonce == issued_nonce)

      sig_hex, certs_hex = parse_binding(binding)
      return result(checks, doc) unless checks.auth(
        "chain + signature present", !sig_hex.empty? && !certs_hex.empty?)

      chain = safe { Attestation::ChainVerifier.parse_chain(certs_hex) } || []
      unless checks.auth("chain parses", !chain.empty?, chain.empty? ? "could not parse cert chain" : "")
        return result(checks, doc)
      end
      leaf = chain.first

      begin
        root = Attestation::ChainVerifier.verify_to_pinned_root(chain, @pinned_roots)
        checks.auth("chain -> pinned Google root", true, root.subject.to_s)
      rescue ArgumentError, OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError => e
        checks.auth("chain -> pinned Google root", false, e.message)
      end

      chal = safe { Attestation::Attestation.challenge(leaf) }
      checks.auth("attestation challenge == nonce",
                  !chal.nil? && chal.unpack1("H*") == issued_nonce.downcase)

      sig_ok = safe do
        pub = leaf.public_key
        pub.verify("SHA256", [sig_hex].pack("H*"), signed)
      end
      checks.auth("signature over verdict", sig_ok == true, sig_ok == true ? "" : "ECDSA verify failed")

      fields = safe { Attestation::Attestation.fields(leaf) }
      checks.integ("hardware security level >= TEE",
                   !fields.nil? && [1, 2].include?(fields.security_level),
                   fields ? Attestation::Attestation.security_level_name(fields.security_level) : "parse error")
      checks.integ("verified boot state = Verified",
                   !fields.nil? && fields.verified_boot_state == 0,
                   fields ? Attestation::Attestation.boot_state_name(fields.verified_boot_state) : "parse error")
      checks.integ("device locked",
                   !fields.nil? && fields.device_locked == true,
                   fields ? fields.device_locked.to_s : "parse error")

      result(checks, doc)
    end

    private

    # The layered verdict: REJECT unless authentic; COMPROMISED on any integrity
    # failure or blocking signal; TRUSTWORTHY only when all three layers clear.
    def result(checks, doc)
      authentic = checks.authentic
      device_ok = checks.device_integrity_ok
      signals = Signals.resolve(doc, @registry, @policy)
      blocking = signals.any?(&:blocking)
      decision = if !authentic then Decision::REJECT
                 elsif !device_ok || blocking then Decision::COMPROMISED
                 else Decision::TRUSTWORTHY
                 end
      VerificationResult.new(
        decision: decision, authentic: authentic, device_integrity_ok: device_ok,
        checks: checks.to_list, schema_version: doc["schemaVersion"],
        point: doc["point"], ts: doc["ts"], nonce: doc["nonce"],
        device: Signals.device(doc), signals: signals,
      )
    end

    def parse_binding(binding)
      sig_hex = ""
      certs_hex = []
      binding.split("\n").each do |line|
        if line.start_with?("SIG#{FS}") then sig_hex = line[4..]
        elsif line.start_with?("CERT#{FS}") then certs_hex << line[5..]
        end
      end
      [sig_hex, certs_hex]
    end

    def safe
      yield
    rescue StandardError
      nil
    end

    # The check ledger: gates record under their layer; the two layer verdicts
    # fall out of the ledger.
    class Checks
      def initialize
        @all = []
      end

      def auth(name, ok, detail = "")
        @all << Check.new(name: name, ok: ok, detail: detail, kind: CheckKind::AUTH)
        ok
      end

      def integ(name, ok, detail = "")
        @all << Check.new(name: name, ok: ok, detail: detail, kind: CheckKind::INTEGRITY)
        ok
      end

      def authentic
        @all.select { |c| c.kind == CheckKind::AUTH }.all?(&:ok)
      end

      def device_integrity_ok
        @all.select { |c| c.kind == CheckKind::INTEGRITY }.all?(&:ok)
      end

      def to_list
        @all.dup
      end
    end
  end
end
end
