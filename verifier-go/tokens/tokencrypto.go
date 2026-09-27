package tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"github.com/iamjosephmj/DeviceIntelligence/verifier-go/attestation"
	"github.com/iamjosephmj/DeviceIntelligence/verifier-go/internal/hexutil"
	"strings"
)

// v2 ECIES token crypto (TokenCryptoV2.kt port) + the v1 discriminator.
// Wire: "2:" + hex(version || epoch || eph_pub(32) || nonce(12) || ct || tag).
// Every corruption fails the GCM tag — a tampered token never decrypts.

const tokenV2Prefix = "2:"
const tokenV2InfoPrefix = "intel-token-v2"

// IsTokenV2 — a v1 token is pure lowercase hex (no ":"); v2 carries "2:".
func IsTokenV2(token string) bool { return strings.HasPrefix(token, tokenV2Prefix) }

// TokenCryptoV2Decrypt opens a "2:" token with the server X25519 private key.
// Errors on tamper (GCM auth), malformed input, and unparseable keys — never
// returns plaintext on any corruption.
func TokenCryptoV2Decrypt(tokenV2 string, serverPriv *ecdh.PrivateKey) ([]byte, error) {
	if !IsTokenV2(tokenV2) {
		return nil, errNotV2
	}
	p, err := hexutil.DecodeHex(tokenV2[len(tokenV2Prefix):])
	if err != nil {
		return nil, err
	}
	const header = 1 + 1 + 32 + 12
	const tag = 16
	if len(p) < header+tag {
		return nil, errTooShort
	}

	version, epoch := p[0], p[1]
	ephPub := p[2:34]
	nonce := p[34:46]
	ctAndTag := p[header:]

	eph := append([]byte(nil), ephPub...)
	eph[31] &= 0x7F // RFC 7748: the ignored high bit
	pub, err := ecdh.X25519().NewPublicKey(eph)
	if err != nil {
		return nil, err
	}
	shared, err := serverPriv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := attestation.HkdfSha256(shared, nonce,
		append([]byte(tokenV2InfoPrefix), epoch), 32)
	if err != nil {
		return nil, err
	}

	aad := []byte{version, epoch}
	aad = append(aad, ephPub...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ctAndTag, aad)
}
