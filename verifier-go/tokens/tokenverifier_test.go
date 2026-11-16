package tokens

import (
	"github.com/iamjosephmj/DeviceIntelligence/verifier-go/policy"
)


import (
	"os"
	"strings"
	"testing"
)

const fixturesDir = "../../verifiers/fixtures"

func TestTokenDecoderDecodesRealChallengeFixture(t *testing.T) {
	raw, err := os.ReadFile(fixturesDir + "/pixel-challenge.token")
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := policy.BundledRegistry()
	decoder := NewTokenDecoder(registry, policy.DefaultPolicy())
	d, err := decoder.Decode(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != 3 || !d.HasBinding {
		t.Fatalf("unexpected decode: %+v", d)
	}
}

func TestTokenDecoderResolveMapsKnownSignal(t *testing.T) {
	registry, _ := policy.BundledRegistry()
	doc := map[string]any{"signals": []any{map[string]any{
		"id": "INTEL_0052", "detail": "x"}}}
	out := resolveSignals(doc, registry, policy.DefaultPolicy())
	if len(out) != 1 || out[0].ID != "INTEL_0052" || out[0].Detector == "?" || out[0].Detail != "x" {
		t.Fatalf("unexpected signal: %+v", out[0])
	}
}

func TestTokenDecoderResolveFallsBackForUnknownSignal(t *testing.T) {
	registry, _ := policy.BundledRegistry()
	doc := map[string]any{"signals": []any{map[string]any{
		"id": "INTEL_9999", "severity": "CRITICAL"}}}
	out := resolveSignals(doc, registry, policy.DefaultPolicy())
	if len(out) != 1 || out[0].ID != "INTEL_9999" || out[0].Detector != "?" ||
		out[0].Severity != "CRITICAL" {
		t.Fatalf("unexpected signal: %+v", out[0])
	}
}
