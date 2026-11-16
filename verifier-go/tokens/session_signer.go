package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// The HMAC-carried session facts a steady-state scan proves possession of.
type Session struct {
	PinnedKeySpkiHex      string
	Assurance             string
	BootState             string
	DeviceLocked          bool
	IssuedAt              int64
	ChainTrusted          bool
	KeyboxRevoked         bool
	CrossLevelReuse       bool
	StrongboxChainMissing bool
	DevicePropMismatch    bool
	BootStateSpoofer      bool
	SoftwareAttested      bool
}

// Stateless HMAC-signed session tokens (SessionSigner.kt port). The token is
// "<payload-b64url>.<mac-b64url>"; tampering with either half fails.
type SessionSigner struct {
	key     []byte
	maxAge  int64
	nowFunc func() int64
}

const DefaultMaxAgeSeconds = 24 * 60 * 60

func NewSessionSigner(key []byte, now func() int64) *SessionSigner {
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	return &SessionSigner{key: key, maxAge: DefaultMaxAgeSeconds, nowFunc: now}
}

type sessionPayload struct {
	PinnedKey    string `json:"pinnedKey"`
	Assurance    string `json:"assurance"`
	Boot         string `json:"boot"`
	Locked       bool   `json:"locked"`
	IssuedAt     int64  `json:"issuedAt"`
	ChainTrusted bool   `json:"chainTrusted"`
	KBRevoked    bool   `json:"kbRevoked"`
	XLReuse      bool   `json:"xlReuse"`
	SBMissing    bool   `json:"sbMissing"`
	PropMismatch bool   `json:"propMismatch"`
	BootSpoofer  bool   `json:"bootSpoofer"`
	SWAttest     bool   `json:"swAttest"`
}

func (s *SessionSigner) Issue(session Session) string {
	payload := sessionPayload{
		PinnedKey: session.PinnedKeySpkiHex, Assurance: session.Assurance,
		Boot: session.BootState, Locked: session.DeviceLocked,
		IssuedAt: session.IssuedAt, ChainTrusted: session.ChainTrusted,
		KBRevoked: session.KeyboxRevoked, XLReuse: session.CrossLevelReuse,
		SBMissing: session.StrongboxChainMissing, PropMismatch: session.DevicePropMismatch,
		BootSpoofer: session.BootStateSpoofer, SWAttest: session.SoftwareAttested,
	}
	raw, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(s.mac(raw))
}

// Open verifies and unwraps a session id; nil on any failure (tamper, wrong
// key, expired, zero timestamp, malformed).
func (s *SessionSigner) Open(sessionID string) *Session {
	dot := -1
	for i := 0; i < len(sessionID); i++ {
		if sessionID[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(sessionID[:dot])
	if err != nil {
		return nil
	}
	macBytes, err := base64.RawURLEncoding.DecodeString(sessionID[dot+1:])
	if err != nil {
		return nil
	}
	expected := s.mac(payload)
	if !hmac.Equal(expected, macBytes) {
		return nil
	}

	var p sessionPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil
	}
	if p.IssuedAt <= 0 || s.nowFunc()-p.IssuedAt > s.maxAge {
		return nil
	}
	return &Session{
		PinnedKeySpkiHex: p.PinnedKey, Assurance: p.Assurance,
		BootState: p.Boot, DeviceLocked: p.Locked, IssuedAt: p.IssuedAt,
		ChainTrusted: p.ChainTrusted, KeyboxRevoked: p.KBRevoked,
		CrossLevelReuse: p.XLReuse, StrongboxChainMissing: p.SBMissing,
		DevicePropMismatch: p.PropMismatch, BootStateSpoofer: p.BootSpoofer,
		SoftwareAttested: p.SWAttest,
	}
}

func (s *SessionSigner) mac(data []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(data)
	return h.Sum(nil)
}
