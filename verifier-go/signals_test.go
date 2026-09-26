package verifier

import (
	"encoding/json"
	"testing"
)

func signalsFixture(t *testing.T, doc string) []ResolvedSignal {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatal(err)
	}
	reg, _ := BundledRegistry()
	return resolveSignals(parsed, reg, DefaultPolicy())
}

func TestSignalsResolvesEnrichmentAttributes(t *testing.T) {
	sig := signalsFixture(t, `{"signals":[{"id":"INTEL_0044","severity":"HIGH","detail":"Injected `+
		`native library. path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so `+
		`module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}`)[0]
	if sig.Attributes["module_id"] != "evilmod" ||
		sig.Attributes["needed"] != "liblog.so,libc.so" ||
		sig.Attributes["links_hook_lib"] != "libdobby.so" ||
		sig.Attributes["path"] != "/data/adb/modules/evilmod/zygisk/arm64-v8a.so" {
		t.Fatalf("unexpected attributes: %+v", sig.Attributes)
	}
}

func TestSignalsResolvesGotHijackSymbolAttributes(t *testing.T) {
	sig := signalsFixture(t, `{"signals":[{"id":"INTEL_0031","severity":"CRITICAL","detail":"hooked `+
		`function pointer. lib=/system/lib64/libbinder.so hooked_symbol=ioctl `+
		`hooked_by=evilmod"}]}`)[0]
	if sig.Attributes["hooked_symbol"] != "ioctl" || sig.Attributes["hooked_by"] != "evilmod" {
		t.Fatalf("unexpected attributes: %+v", sig.Attributes)
	}
}

func TestSignalsCorrelatesDefinitiveHookStructuralPlusBehavioral(t *testing.T) {
	doc := `{"signals":[{"id":"INTEL_0003","severity":"CRITICAL","detail":"inline ` +
		`hook. hooked_symbol=faccessat hooked_by=evilmod"},{"id":"INTEL_0059",` +
		`"severity":"HIGH","detail":"lie. hooked_symbol=faccessat ` +
		`path=/system/bin/sh"},{"id":"INTEL_0003","severity":"CRITICAL",` +
		`"detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}]}`
	hooks := definitiveHooks(signalsFixture(t, doc))
	if len(hooks) != 1 || hooks[0] != "faccessat" {
		t.Fatalf("got %v, want [faccessat]", hooks)
	}
}

func TestSignalsUnknownSignalFallsBackToQuestionMarks(t *testing.T) {
	sig := signalsFixture(t, `{"signals":[{"id":"INTEL_9999","severity":"CRITICAL"}]}`)[0]
	if sig.Detector != "?" || sig.Kind != "?" || sig.Severity != "CRITICAL" {
		t.Fatalf("unexpected signal: %+v", sig)
	}
}

func TestSignalsLegacySigPrefixBridgesToIntel(t *testing.T) {
	sig := signalsFixture(t, `{"signals":[{"id":"SIG_0052","severity":"CRITICAL"}]}`)[0]
	if sig.ID != "INTEL_0052" {
		t.Fatalf("got %s", sig.ID)
	}
}
