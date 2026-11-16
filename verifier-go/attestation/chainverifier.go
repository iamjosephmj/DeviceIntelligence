package attestation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// Token attestation chain validation (ChainVerifier.kt port). Signature-only:
// each cert signed by the next, and the chain top must terminate in a pinned
// Google root (by SHA-256 of the DER, or by key verification — Pixel chains
// mix EC keyboxes with RSA Google intermediates).

func ParseChain(certsHex []string) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(certsHex))
	for _, h := range certsHex {
		der, err := decodeHex(h)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

func sha256Fp(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// VerifyToPinnedRoot returns the pinned root the chain terminates in, or an
// error when no pinned root accepts it.
func VerifyToPinnedRoot(chain []*x509.Certificate, pinned []*x509.Certificate) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errEmptyChain
	}
	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, err
		}
	}
	top := chain[len(chain)-1]
	topFp := sha256Fp(top)
	for _, root := range pinned {
		if topFp == sha256Fp(root) {
			return root, nil
		}
		if err := top.CheckSignatureFrom(root); err == nil {
			return root, nil
		}
	}
	return nil, errNoPinned
}
