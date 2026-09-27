package tokens

import (
	"github.com/iamjosephmj/DeviceIntelligence/verifier-go/model"
)


import (
	"os"
	"strings"
	"testing"
)

// Offline parity against a REAL token captured from the rooted Pixel 6 Pro
// (KernelSU + TrickyStore). The Go verifier must grade this exact token+nonce
// COMPROMISED, identically to the Kotlin reference and the other ports.
func TestPixelRealTokenParityCompromised(t *testing.T) {
	tokenBytes, err := os.ReadFile(fixturesDir + "/pixel-token.hex")
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes, err := os.ReadFile(fixturesDir + "/pixel-nonce.hex")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	nonce := strings.TrimSpace(string(nonceBytes))

	verifier, err := NewTokenVerifierBundled()
	if err != nil {
		t.Fatal(err)
	}
	res, err := verifier.Verify(token, nonce)
	if err != nil {
		t.Fatal(err)
	}

	if !res.Authentic {
		t.Fatal("token must be authentic")
	}
	if res.DeviceIntegrityOK {
		t.Fatal("device integrity must fail on the rooted pixel")
	}
	if res.Decision != model.DecisionCompromised {
		t.Fatalf("decision = %s, want COMPROMISED", res.Decision)
	}

	// The token is a registryVersion-1 capture: its attestation signal carries
	// the pre-reshuffle code, which the v2 table resolves to whatever row owns
	// that number today.
	found0000 := false
	for _, s := range res.Signals {
		if s.ID == "INTEL_0000" {
			found0000 = true
			if !s.Blocking {
				t.Fatal("INTEL_0000 must be blocking")
			}
		}
	}
	if !found0000 {
		t.Fatal("INTEL_0000 signal missing")
	}

	checks := map[string]bool{}
	for _, c := range res.Checks {
		checks[c.Name] = c.OK
	}
	if !checks["binding present"] || !checks["nonce matches issued"] ||
		!checks["chain -> pinned Google root"] || !checks["signature over verdict"] {
		t.Fatalf("auth checks unexpectedly failing: %+v", checks)
	}
	if checks["verified boot state = Verified"] {
		t.Fatal("the rooted pixel must not verify its boot state")
	}
}
