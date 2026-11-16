package tokens

import (
	"crypto/ecdh"

	"github.com/iamjosephmj/DeviceIntelligence/verifier-go/internal/hexutil"
	"encoding/hex"
	"testing"
)

const serverPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

const nativeV2Token = "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d10111213" +
	"1415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a" +
	"2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b"

const emptyV2Token = "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d1011" +
	"12131415161718191a1b9a7f7296f43354e241400ee7b8946c46"

const expectedV2Plaintext = "signed_content\n--BINDING\nSIG...\nCERT..."

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex literal: %v", err)
	}
	return b
}

func serverKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(mustHex(t, serverPrivHex))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func flipAt(t *testing.T, token string, i int) string {
	t.Helper()
	body := []byte(token[2:])
	if body[i] == '0' {
		body[i] = '1'
	} else {
		body[i] = '0'
	}
	return "2:" + string(body)
}

func TestDecryptsNativeV2Token(t *testing.T) {
	out, err := TokenCryptoV2Decrypt(nativeV2Token, serverKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != expectedV2Plaintext {
		t.Fatalf("got %q", string(out))
	}
}

func TestDecryptsEmptyCiphertextToken(t *testing.T) {
	out, err := TokenCryptoV2Decrypt(emptyV2Token, serverKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("got %d bytes", len(out))
	}
}

func TestTamperFails(t *testing.T) {
	for _, i := range []int{0, 2, 10, 70, 92} {
		if _, err := TokenCryptoV2Decrypt(flipAt(t, nativeV2Token, i), serverKey(t)); err == nil {
			t.Fatalf("tamper at %d must fail the gcm tag", i)
		}
	}
}

func TestTamperTagFails(t *testing.T) {
	if _, err := TokenCryptoV2Decrypt(flipAt(t, nativeV2Token, len(nativeV2Token)-3), serverKey(t)); err == nil {
		t.Fatal("tag tamper must fail")
	}
}

func TestWrongServerKeyFails(t *testing.T) {
	other := "0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"
	key, err := ecdh.X25519().NewPrivateKey(mustHex(t, other))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TokenCryptoV2Decrypt(nativeV2Token, key); err == nil {
		t.Fatal("wrong key must fail")
	}
}

func TestAllZeroEphemeralPointThrows(t *testing.T) {
	body := []byte(nativeV2Token[2:])
	for i := 4; i < 68; i++ {
		body[i] = '0'
	}
	if _, err := TokenCryptoV2Decrypt("2:"+string(body), serverKey(t)); err == nil {
		t.Fatal("all-zero ephemeral must fail")
	}
}

func TestRejectsMissingPrefix(t *testing.T) {
	if _, err := TokenCryptoV2Decrypt("deadbeefcafe", serverKey(t)); err != errNotV2 {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsTooShortPayload(t *testing.T) {
	if _, err := TokenCryptoV2Decrypt("2:0203", serverKey(t)); err == nil {
		t.Fatal("too-short payload must fail")
	}
}

func TestRejectsOddLengthHex(t *testing.T) {
	if _, err := TokenCryptoV2Decrypt("2:abc", serverKey(t)); err == nil {
		t.Fatal("odd-length hex must fail")
	}
}

func TestRejectsNonHexChars(t *testing.T) {
	if _, err := TokenCryptoV2Decrypt("2:zzzz", serverKey(t)); err == nil {
		t.Fatal("non-hex chars must fail")
	}
}

func TestIsV2DiscriminatesFromV1(t *testing.T) {
	if !IsTokenV2(nativeV2Token) {
		t.Fatal("v2 token must discriminate")
	}
	if IsTokenV2("deadbeefcafe") || IsTokenV2("") || IsTokenV2("2") {
		t.Fatal("v1-shaped inputs must not discriminate as v2")
	}
}

func TestDecodeHexRejectsBadChars(t *testing.T) {
	if _, err := hexutil.DecodeHex("zz"); err != hexutil.ErrBadHex {
		t.Fatalf("got %v", err)
	}
	if _, err := hexutil.DecodeHex("abc"); err != hexutil.ErrOddHex {
		t.Fatalf("got %v", err)
	}
	if got := hex.EncodeToString(mustHex(t, "deadbeef")); got != "deadbeef" {
		t.Fatal("round trip")
	}
}
