package verifier

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func fullSessionFixture() ScanSession {
	id := "cc" + strings.Repeat("c", 62)
	aid := "dd" + strings.Repeat("d", 62)
	aa := "aa" + strings.Repeat("a", 62)
	bb := "bb" + strings.Repeat("b", 62)
	return ScanSession{
		AttestedKey: "3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb",
		AttestedApp: &AttestedApp{
			PackageNames:      []string{"com.example.app", "com.example.other"},
			SignatureDigests:  []string{aa, bb},
		},
		Assurance: "STRONGBOX", BootState: "Verified", DeviceLocked: true,
		ChainTrusted: true, KeyboxRevoked: false, CrossLevelReuse: false,
		DevicePropMismatch: false, BootStateSpoofer: false,
		StrongboxChainMissing: false, SoftwareAttested: false,
		OsPatchLevel:     intPtr(202604),
		VendorPatchLevel: intPtr(20260405),
		BootPatchLevel:   intPtr(20260405),
		Fingerprint: &DeviceFingerprint{
			ID: strPtr(id), Aid: strPtr(aid), SecurityLevel: strPtr("L1"),
			Build:     strPtr("google/raven/raven:16/BP41.250:user/release-keys"),
			Kernel:    strPtr("6.1.145-android14-11"),
			Patch:     strPtr("2026-04-05"),
			Installer: strPtr("com.android.vending"),
		},
	}
}

func strPtr(s string) *string { return &s }
func intPtr(n int) *int       { return &n }

func TestCodecFullSessionRoundTripsFieldForField(t *testing.T) {
	session := fullSessionFixture()
	decoded, err := DecodeScanSession(EncodeScanSession(session))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, session) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", decoded, session)
	}
}

func TestCodecCompromisedFlagsRoundTrip(t *testing.T) {
	bad := ScanSession{
		AttestedKey: "00", AttestedApp: nil, Assurance: "SOFTWARE",
		BootState: "Unverified", DeviceLocked: false, ChainTrusted: false,
		KeyboxRevoked: true, CrossLevelReuse: true, DevicePropMismatch: true,
		BootStateSpoofer: true, StrongboxChainMissing: true,
		SoftwareAttested: true, OsPatchLevel: nil, VendorPatchLevel: nil,
		BootPatchLevel: nil, Fingerprint: nil,
	}
	decoded, err := DecodeScanSession(EncodeScanSession(bad))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, bad) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", decoded, bad)
	}
}

func TestCodecStringsNeedingEscapesSurvive(t *testing.T) {
	build := `a"quote\and/slash`
	odd := ScanSession{
		AttestedKey: "00", AttestedApp: nil, Assurance: "TEE",
		BootState: "Verified", DeviceLocked: true, ChainTrusted: true,
		KeyboxRevoked: false, CrossLevelReuse: false, DevicePropMismatch: false,
		BootStateSpoofer: false, StrongboxChainMissing: false,
		SoftwareAttested: false, OsPatchLevel: nil, VendorPatchLevel: nil,
		BootPatchLevel: nil,
		Fingerprint: &DeviceFingerprint{
			ID: nil, Aid: nil, SecurityLevel: nil, Build: &build,
			Kernel: nil, Patch: nil, Installer: nil,
		},
	}
	decoded, err := DecodeScanSession(EncodeScanSession(odd))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, odd) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", decoded, odd)
	}
}

func TestCodecDecodesPythonBackendShape(t *testing.T) {
	raw, err := os.ReadFile("../verifiers/fixtures/py-session.json")
	if err != nil {
		t.Skip("fixture not available")
	}
	s, err := DecodeScanSession(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if s.Assurance != "STRONGBOX" || s.BootState != "SelfSigned" {
		t.Fatalf("unexpected session: %+v", s)
	}
	if !s.BootStateSpoofer || !s.DeviceLocked || !s.ChainTrusted {
		t.Fatal("expected spoofer + locked + chainTrusted")
	}
	if s.KeyboxRevoked || s.CrossLevelReuse || s.DevicePropMismatch || s.SoftwareAttested {
		t.Fatal("unexpected compromised flags")
	}
	if s.OsPatchLevel == nil || *s.OsPatchLevel != 202604 ||
		s.VendorPatchLevel == nil || *s.VendorPatchLevel != 20260405 ||
		s.BootPatchLevel == nil || *s.BootPatchLevel != 20260405 {
		t.Fatal("patch levels mismatch")
	}
	if s.AttestedApp == nil || len(s.AttestedApp.PackageNames) != 1 ||
		s.AttestedApp.PackageNames[0] != "tech.thessemaj.deviceintelligence.sample" {
		t.Fatalf("unexpected app: %+v", s.AttestedApp)
	}
	if s.Fingerprint == nil || s.Fingerprint.SecurityLevel == nil ||
		*s.Fingerprint.SecurityLevel != "L1" || s.Fingerprint.Installer != nil {
		t.Fatalf("unexpected fingerprint: %+v", s.Fingerprint)
	}
	if !strings.HasPrefix(*s.Fingerprint.Build, "google/raven/raven:16") {
		t.Fatalf("unexpected build: %s", *s.Fingerprint.Build)
	}
}

func TestCodecMalformedDocumentIsRejected(t *testing.T) {
	if _, err := DecodeScanSession(`{"assurance":"TEE"}`); err == nil {
		t.Fatal("malformed document must be rejected")
	}
}
