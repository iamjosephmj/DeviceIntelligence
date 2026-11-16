package tokens

import "testing"

const issuedAt = int64(1_787_220_000)

func fixtureSession() Session {
	return Session{
		PinnedKeySpkiHex: "30591301deadbeef", Assurance: "STRONGBOX",
		BootState: "Verified", DeviceLocked: true, IssuedAt: issuedAt,
	}
}

func TestSessionSignerRoundTrips(t *testing.T) {
	signer := NewSessionSigner([]byte(LabServerKey), func() int64 { return issuedAt + 100 })
	opened := signer.Open(signer.Issue(fixtureSession()))
	if opened == nil {
		t.Fatal("open returned nil")
	}
	if *opened != fixtureSession() {
		t.Fatalf("round trip mismatch: %+v", *opened)
	}
}

func TestSessionSignerRejectsExpired(t *testing.T) {
	signer := NewSessionSigner([]byte(LabServerKey), func() int64 { return issuedAt })
	late := NewSessionSigner([]byte(LabServerKey),
		func() int64 { return issuedAt + DefaultMaxAgeSeconds + 1 })
	if late.Open(signer.Issue(fixtureSession())) != nil {
		t.Fatal("expired session must not open")
	}
}

func TestSessionSignerRejectsZeroTimestamp(t *testing.T) {
	zero := NewSessionSigner([]byte(LabServerKey), func() int64 { return 0 })
	stampless := fixtureSession()
	stampless.IssuedAt = 0
	opener := NewSessionSigner([]byte(LabServerKey), func() int64 { return issuedAt + 100 })
	if opener.Open(zero.Issue(stampless)) != nil {
		t.Fatal("zero-issuedAt session must not open")
	}
}

func TestSessionSignerRejectsTamperedPayload(t *testing.T) {
	signer := NewSessionSigner([]byte(LabServerKey), func() int64 { return issuedAt + 100 })
	sessionID := signer.Issue(fixtureSession())
	payload := sessionID[:indexByte(sessionID, '.')]
	mac := sessionID[indexByte(sessionID, '.')+1:]
	last := payload[len(payload)-1]
	if last == 'A' {
		last = 'B'
	} else {
		last = 'A'
	}
	forged := payload[:len(payload)-1] + string(last) + "." + mac
	if signer.Open(forged) != nil {
		t.Fatal("tampered payload must not open")
	}
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func TestSessionSignerRejectsWrongKey(t *testing.T) {
	signer := NewSessionSigner([]byte(LabServerKey), func() int64 { return issuedAt + 100 })
	forged := NewSessionSigner([]byte("different-key"), func() int64 { return issuedAt + 100 })
	if forged.Open(signer.Issue(fixtureSession())) != nil {
		t.Fatal("wrong key must not open")
	}
}

func TestSessionSignerRejectsMalformed(t *testing.T) {
	signer := NewSessionSigner([]byte(LabServerKey), func() int64 { return issuedAt + 100 })
	if signer.Open("not-a-session") != nil {
		t.Fatal("malformed session id must not open")
	}
}
