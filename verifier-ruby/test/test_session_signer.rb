# frozen_string_literal: true

require "minitest/autorun"
require "deviceintelligence_verifier"

class SessionSignerTest < Minitest::Test
  SERVER_KEY = "intel-lab-session-key-v1"
  ISSUED_AT = 1_787_220_000

  def session(issued_at: ISSUED_AT)
    DeviceIntelligenceVerifier::Session.new(
      pinned_key_spki_hex: "30591301deadbeef",
      assurance: "STRONGBOX", boot_state: "Verified", device_locked: true,
      issued_at: issued_at, chain_trusted: false, keybox_revoked: false,
      cross_level_reuse: false, strongbox_chain_missing: false,
      device_prop_mismatch: false, boot_state_spoofer: false,
      software_attested: false)
  end

  def signer_at(now)
    DeviceIntelligenceVerifier::SessionSigner.new(SERVER_KEY, now: -> { now })
  end

  def max_age
    DeviceIntelligenceVerifier::SessionSigner::DEFAULT_MAX_AGE_SECONDS
  end

  def test_round_trips
    signer = signer_at(ISSUED_AT + 100)
    opened = signer.open(signer.issue(session))
    assert_equal session, opened
  end

  def test_rejects_expired
    signer = signer_at(ISSUED_AT)
    late = signer_at(ISSUED_AT + max_age + 1)
    assert_nil late.open(signer.issue(session))
  end

  def test_rejects_zero_timestamp
    zero = signer_at(0)
    opener = signer_at(ISSUED_AT + 100)
    assert_nil opener.open(zero.issue(session(issued_at: 0)))
  end

  def test_rejects_tampered_payload
    signer = signer_at(ISSUED_AT + 100)
    session_id = signer.issue(session)
    payload, mac = session_id.split(".", 2)
    forged = payload[0..-2] + (payload.end_with?("A") ? "B" : "A") + "." + mac
    assert_nil signer.open(forged)
  end

  def test_rejects_wrong_key
    signer = signer_at(ISSUED_AT + 100)
    forged_signer = DeviceIntelligenceVerifier::SessionSigner.new(
      "different-key", now: -> { ISSUED_AT + 100 })
    assert_nil forged_signer.open(signer.issue(session))
  end

  def test_rejects_malformed
    signer = signer_at(ISSUED_AT + 100)
    assert_nil signer.open("not-a-session")
  end
end
