from deviceintelligence_verifier.lab_keys import SERVER_KEY
from deviceintelligence_verifier.models import Assurance, Session
from deviceintelligence_verifier.session_signer import SessionSigner

ISSUED_AT = 1_787_220_000
SESSION = Session("30591301deadbeef", Assurance.STRONGBOX, "Verified", True, ISSUED_AT)


def signer_at(now):
    return SessionSigner(SERVER_KEY, now=lambda: now)


def test_round_trips():
    signer = SessionSigner(SERVER_KEY, now=lambda: ISSUED_AT + 100)
    assert signer.open(signer.issue(SESSION)) == SESSION


def test_rejects_expired():
    signer = SessionSigner(SERVER_KEY, now=lambda: ISSUED_AT)
    late = SessionSigner(SERVER_KEY,
                         now=lambda: ISSUED_AT + signer_max_age() + 1)
    assert late.open(signer.issue(SESSION)) is None


def signer_max_age():
    from deviceintelligence_verifier.session_signer import DEFAULT_MAX_AGE_SECONDS
    return DEFAULT_MAX_AGE_SECONDS


def test_rejects_zero_timestamp():
    stampless = Session("30591301deadbeef", Assurance.STRONGBOX, "Verified", True, 0)
    assert signer_at(ISSUED_AT + 100).open(stampless and signer_at(0).issue(stampless)) is None


def test_rejects_tampered_payload():
    signer = SessionSigner(SERVER_KEY, now=lambda: ISSUED_AT + 100)
    session_id = signer.issue(SESSION)
    payload, mac = session_id.split(".", 1)
    forged = payload[:-1] + ("B" if payload[-1] == "A" else "A") + "." + mac
    assert signer.open(forged) is None


def test_rejects_wrong_key():
    signer = SessionSigner(SERVER_KEY, now=lambda: ISSUED_AT + 100)
    forged_signer = SessionSigner(b"different-key", now=lambda: ISSUED_AT + 100)
    assert forged_signer.open(signer.issue(SESSION)) is None


def test_rejects_malformed():
    signer = SessionSigner(SERVER_KEY, now=lambda: ISSUED_AT + 100)
    assert signer.open("not-a-session") is None
