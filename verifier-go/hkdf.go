package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HKDF-SHA256 (RFC 5869) — extract-and-expand on the stdlib HMAC/SHA-256.
// (crypto/hkdf landed in Go 1.24; the module targets 1.22.)
func hkdfSha256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*32 {
		return nil, errOutOfRange
	}
	if len(salt) == 0 {
		salt = make([]byte, 32) // RFC convention: zero-filled salt of hash length
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)

	out := make([]byte, 0, length)
	var prev []byte
	for i := 1; len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length], nil
}

type hexError string

func (e hexError) Error() string { return string(e) }

const (
	errOutOfRange  = hexError("HKDF outLen out of range")
	errOddHex      = hexError("odd-length hex")
	errBadHex      = hexError("bad hex char")
	errNotV2       = hexError("not a v2 token")
	errTooShort    = hexError("v2 token too short")
	errEmptyChain  = hexError("empty chain")
	errNoPinned    = hexError("chain top does not chain to a pinned Google root")
	errNoChallenge = hexError("KeyDescription too short")
)

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errOddHex
	}
	out := make([]byte, len(s)/2)
	const hexDigits = "0123456789abcdefABCDEF"
	for i := 0; i < len(s); i += 2 {
		hi := indexByte2(hexDigits, s[i])
		lo := indexByte2(hexDigits, s[i+1])
		if hi < 0 || lo < 0 {
			return nil, errBadHex
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out, nil
}

func indexByte2(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
