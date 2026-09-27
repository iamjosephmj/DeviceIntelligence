package tokens

import (
	"crypto/ecdh"
	"encoding/pem"
)

// Loads the backend X25519 private half (ServerKey.kt port). Accepts PEM
// PKCS#8 or raw DER; a truncated tail-32 fallback mirrors the Kotlin no-XDH
// path for exotic encodings.
func ServerKeyFromBytes(data []byte) (*ecdh.PrivateKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	if key, err := ecdh.X25519().NewPrivateKey(data); err == nil {
		return key, nil
	}
	if len(data) < 32 {
		return nil, hexError("PKCS#8 X25519 key too short")
	}
	// The tail-32 fallback: the raw scalar is the last 32 bytes.
	return ecdh.X25519().NewPrivateKey(data[len(data)-32:])
}
