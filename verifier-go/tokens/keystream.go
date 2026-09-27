package tokens

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/iamjosephmj/DeviceIntelligence/verifier-go/internal/hexutil"
)

// v1 symmetric token crypto (Keystream.kt port). Confidentiality in transit
// only — the scan path rejects v1 tokens; this decodes legacy ones.
const keystreamPhrase = "intel-verdict-token-key-v1" // WIRE-CONSTANT (do NOT rebrand)

// KeystreamDecryptHex recovers the plaintext of a v1 (legacy) token.
func KeystreamDecryptHex(tokenHex string) (string, error) {
	cipher, err := hexutil.DecodeHex(tokenHex)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256([]byte(keystreamPhrase))
	plain := make([]byte, len(cipher))
	var block uint32
	for off := 0; off < len(cipher); off += 32 {
		var ib [4]byte
		binary.LittleEndian.PutUint32(ib[:], block)
		ks := sha256.Sum256(append(key[:], ib[:]...))
		take := min(32, len(cipher)-off)
		for i := 0; i < take; i++ {
			plain[off+i] = cipher[off+i] ^ ks[i]
		}
		block++
	}
	return string(plain), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
