// Package hexutil — the shared hex decoder every envelope and chain parser
// uses. Errors are sentinel values so callers can compare identity.
package hexutil

import "errors"

var (
	ErrOddHex = errors.New("odd-length hex")
	ErrBadHex = errors.New("bad hex char")
)

// DecodeHex decodes a hex string, rejecting odd lengths and non-hex bytes.
func DecodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, ErrOddHex
	}
	out := make([]byte, len(s)/2)
	const hexDigits = "0123456789abcdefABCDEF"
	for i := 0; i < len(s); i += 2 {
		hi := indexByte2(hexDigits, s[i])
		lo := indexByte2(hexDigits, s[i+1])
		if hi < 0 || lo < 0 {
			return nil, ErrBadHex
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
