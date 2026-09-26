package verifier

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := decodeHex(s)
	if err != nil {
		t.Fatalf("bad hex literal: %v", err)
	}
	return b
}

func TestHkdfRFC5869Case1(t *testing.T) {
	okm, err := hkdfSha256(mustHex(t, strings.Repeat("0b", 22)),
		mustHex(t, "000102030405060708090a0b0c"),
		mustHex(t, "f0f1f2f3f4f5f6f7f8f9"), 42)
	if err != nil {
		t.Fatal(err)
	}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865"
	if got := hex.EncodeToString(okm); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestHkdfRFC5869Case3EmptySaltAndInfo(t *testing.T) {
	okm, err := hkdfSha256(mustHex(t, strings.Repeat("0b", 22)), nil, nil, 42)
	if err != nil {
		t.Fatal(err)
	}
	want := "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
		"9d201395faa4b61a96c8"
	if got := hex.EncodeToString(okm); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestHkdfRejectsOutputOver255Blocks(t *testing.T) {
	if _, err := hkdfSha256([]byte{1}, nil, nil, 255*32+1); err == nil {
		t.Fatal("expected outLen range error")
	}
}

func TestHkdfTokenDerivationShapeIs32Bytes(t *testing.T) {
	key, err := hkdfSha256(mustHex(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		mustHex(t, "101010101010101010101010"), []byte("intel-token-v2\x00"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("got %d bytes", len(key))
	}
}
