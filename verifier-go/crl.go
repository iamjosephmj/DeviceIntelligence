package verifier

import "crypto/x509"

// Attestation-key revocation list (the weekly-baked encrypted crl.bin asset,
// already decrypted by the caller). Serial matching normalizes case, an
// optional 0x prefix, and leading zeros away — "0" stays "0".
type AttestationCrl struct {
	revoked map[string]bool
}

func normalizeSerial(serialHex string) string {
	s := upper(serialHex)
	s = trimPrefix(s, "0X")
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	if len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func ParseAttestationCrl(text string) *AttestationCrl {
	revoked := map[string]bool{}
	for _, line := range splitLines(text) {
		n := normalizeSerial(stripComment(line))
		if n != "" {
			revoked[n] = true
		}
	}
	return &AttestationCrl{revoked: revoked}
}

func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' {
			return line[:i]
		}
	}
	return line
}

func splitLines(text string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			out = append(out, text[start:i])
			start = i + 1
		}
	}
	if start < len(text) {
		out = append(out, text[start:])
	}
	return out
}

func (c *AttestationCrl) Revoked(serialHex string) bool {
	return c.revoked[normalizeSerial(serialHex)]
}

func (c *AttestationCrl) RevokedCert(cert *x509.Certificate) bool {
	return c.Revoked(cert.SerialNumber.Text(16))
}

func (c *AttestationCrl) Size() int { return len(c.revoked) }
