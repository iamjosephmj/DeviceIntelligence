package verifier

import "testing"

func TestBundledRegistryLoadsTheActiveRows(t *testing.T) {
	reg, err := BundledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if reg.Size() != 61 {
		t.Fatalf("registry size = %d, want 61", reg.Size())
	}
}

func TestRegistryResolvesACodeToItsMeaning(t *testing.T) {
	reg, _ := BundledRegistry()
	meta, ok := reg.Get("INTEL_0042")
	if !ok {
		t.Fatal("INTEL_0042 missing")
	}
	if meta.Detector != "native_integrity" || meta.Kind != "text_integrity_divergence" ||
		meta.Severity != "CRITICAL" {
		t.Fatalf("unexpected meta: %+v", meta)
	}
}

func TestRegistryRetiredCodesAreAbsent(t *testing.T) {
	reg, _ := BundledRegistry()
	if _, ok := reg.Get("INTEL_0020"); ok {
		t.Fatal("INTEL_0020 retired but present")
	}
	if _, ok := reg.Get("INTEL_0039"); ok {
		t.Fatal("INTEL_0039 retired but present")
	}
}

func TestRegistryUnknownCodesResolveToQuestionMarks(t *testing.T) {
	reg, err := RegistryFromJSON(`{"signals":[{"id":"INTEL_9999"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := reg.Get("INTEL_9999")
	if !ok || row.Detector != "?" || row.Kind != "?" {
		t.Fatalf("unexpected row: %+v", row)
	}
}

func TestRegistryNilSafeGet(t *testing.T) {
	reg, _ := BundledRegistry()
	if _, ok := reg.Get(""); ok {
		t.Fatal("empty id must not resolve")
	}
}
