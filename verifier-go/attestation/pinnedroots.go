package attestation

import (
	_ "embed"
	"crypto/x509"
	"encoding/base64"
	"strings"
)

// The pinned Google hardware-attestation roots (PinnedRoots.kt port).
// Bundled file: base64 DER, one root per line, '#' comments allowed.

//go:embed resources/pinned-roots.txt
var pinnedRootsTxt string

func ParsePinnedRoots(text string) ([]*x509.Certificate, error) {
	roots := []*x509.Certificate{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		roots = append(roots, cert)
	}
	return roots, nil
}

func DefaultPinnedRoots() ([]*x509.Certificate, error) {
	return ParsePinnedRoots(pinnedRootsTxt)
}
