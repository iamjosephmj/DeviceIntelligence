package scan

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// JSON round-trip for ScanSession (ScanSessionCodec.kt port). Decode grades a
// truncated document DOWN to the suspicious value, never to the benign default
// — a missing boolean always reads as the dangerous one.

type AttestedApp struct {
	PackageNames     []string
	SignatureDigests []string
}

type DeviceFingerprint struct {
	ID            *string
	Aid           *string
	SecurityLevel *string
	Build         *string
	Kernel        *string
	Patch         *string
	Installer     *string
}

type ScanSession struct {
	AttestedKey           string
	AttestedApp           *AttestedApp
	Assurance             string
	BootState             string
	DeviceLocked          bool
	ChainTrusted          bool
	KeyboxRevoked         bool
	CrossLevelReuse       bool
	DevicePropMismatch    bool
	BootStateSpoofer      bool
	StrongboxChainMissing bool
	SoftwareAttested      bool
	OsPatchLevel          *int
	VendorPatchLevel      *int
	BootPatchLevel        *int
	Fingerprint           *DeviceFingerprint
}

var errNoAttestedKey = errors.New("session has no attestedKey")

func jsonBoolDown(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func jsonBoolUp(v any) bool {
	b, ok := v.(bool)
	return !ok || b // absent grades DOWN to the suspicious value
}

func jsonIntPtr(v any) *int {
	if f, ok := v.(float64); ok {
		n := int(f)
		return &n
	}
	return nil
}

func jsonStrPtr(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func DecodeScanSession(jsonText string) (ScanSession, error) {
	var o map[string]any
	if err := json.Unmarshal([]byte(jsonText), &o); err != nil {
		return ScanSession{}, err
	}
	key, ok := o["attestedKey"].(string)
	if !ok {
		return ScanSession{}, errNoAttestedKey
	}
	s := ScanSession{
		AttestedKey:           key,
		BootState:             jsonString(o["bootState"]),
		DeviceLocked:          jsonBoolDown(o["deviceLocked"]),
		ChainTrusted:          jsonBoolDown(o["chainTrusted"]),
		KeyboxRevoked:         jsonBoolUp(o["keyboxRevoked"]),
		CrossLevelReuse:       jsonBoolUp(o["crossLevelReuse"]),
		DevicePropMismatch:    jsonBoolUp(o["devicePropMismatch"]),
		BootStateSpoofer:      jsonBoolUp(o["bootStateSpoofer"]),
		StrongboxChainMissing: jsonBoolUp(o["strongboxChainMissing"]),
		SoftwareAttested:      jsonBoolUp(o["softwareAttested"]),
		OsPatchLevel:          jsonIntPtr(o["osPatchLevel"]),
		VendorPatchLevel:      jsonIntPtr(o["vendorPatchLevel"]),
		BootPatchLevel:        jsonIntPtr(o["bootPatchLevel"]),
	}
	switch o["assurance"] {
	case "TEE":
		s.Assurance = "TEE"
	case "STRONGBOX":
		s.Assurance = "STRONGBOX"
	default:
		s.Assurance = "SOFTWARE"
	}
	if app, ok := o["attestedApp"].(map[string]any); ok {
		app2 := &AttestedApp{}
		if pk, ok := app["packageNames"].([]any); ok {
			for _, v := range pk {
				if str, ok := v.(string); ok {
					app2.PackageNames = append(app2.PackageNames, str)
				}
			}
		}
		if sd, ok := app["signatureDigests"].([]any); ok {
			for _, v := range sd {
				if str, ok := v.(string); ok {
					app2.SignatureDigests = append(app2.SignatureDigests, str)
				}
			}
		}
		s.AttestedApp = app2
	}
	if fp, ok := o["fingerprint"].(map[string]any); ok {
		s.Fingerprint = &DeviceFingerprint{
			ID:            jsonStrPtr(fp["id"]),
			Aid:           jsonStrPtr(fp["aid"]),
			SecurityLevel: jsonStrPtr(fp["securityLevel"]),
			Build:         jsonStrPtr(fp["build"]),
			Kernel:        jsonStrPtr(fp["kernel"]),
			Patch:         jsonStrPtr(fp["patch"]),
			Installer:     jsonStrPtr(fp["installer"]),
		}
	}
	return s, nil
}

func jsonStringOrNull(v *string) string {
	if v == nil {
		return "null"
	}
	return jsonQuote(*v)
}

func jsonString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func jsonStringArray(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = jsonQuote(item)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func EncodeScanSession(s ScanSession) string {
	var b strings.Builder
	b.WriteString(`{"attestedKey":`)
	b.WriteString(jsonQuote(s.AttestedKey))
	if s.AttestedApp == nil {
		b.WriteString(`,"attestedApp":null`)
	} else {
		b.WriteString(`,"attestedApp":{"packageNames":`)
		b.WriteString(jsonStringArray(s.AttestedApp.PackageNames))
		b.WriteString(`,"signatureDigests":`)
		b.WriteString(jsonStringArray(s.AttestedApp.SignatureDigests))
		b.WriteString("}")
	}
	b.WriteString(`,"assurance":"` + string(s.Assurance) + `"`)
	b.WriteString(`,"bootState":` + jsonQuote(s.BootState))
	b.WriteString(`,"deviceLocked":` + boolJSON(s.DeviceLocked))
	b.WriteString(`,"chainTrusted":` + boolJSON(s.ChainTrusted))
	b.WriteString(`,"keyboxRevoked":` + boolJSON(s.KeyboxRevoked))
	b.WriteString(`,"crossLevelReuse":` + boolJSON(s.CrossLevelReuse))
	b.WriteString(`,"devicePropMismatch":` + boolJSON(s.DevicePropMismatch))
	b.WriteString(`,"bootStateSpoofer":` + boolJSON(s.BootStateSpoofer))
	b.WriteString(`,"strongboxChainMissing":` + boolJSON(s.StrongboxChainMissing))
	b.WriteString(`,"softwareAttested":` + boolJSON(s.SoftwareAttested))
	b.WriteString(`,"osPatchLevel":` + intOrNull(s.OsPatchLevel))
	b.WriteString(`,"vendorPatchLevel":` + intOrNull(s.VendorPatchLevel))
	b.WriteString(`,"bootPatchLevel":` + intOrNull(s.BootPatchLevel))
	if s.Fingerprint == nil {
		b.WriteString(`,"fingerprint":null`)
	} else {
		fp := s.Fingerprint
		b.WriteString(`,"fingerprint":{"id":` + jsonStringOrNull(fp.ID))
		b.WriteString(`,"aid":` + jsonStringOrNull(fp.Aid))
		b.WriteString(`,"securityLevel":` + jsonStringOrNull(fp.SecurityLevel))
		b.WriteString(`,"build":` + jsonStringOrNull(fp.Build))
		b.WriteString(`,"kernel":` + jsonStringOrNull(fp.Kernel))
		b.WriteString(`,"patch":` + jsonStringOrNull(fp.Patch))
		b.WriteString(`,"installer":` + jsonStringOrNull(fp.Installer))
		b.WriteString("}")
	}
	b.WriteString("}")
	return b.String()
}

func boolJSON(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func intOrNull(v *int) string {
	if v == nil {
		return "null"
	}
	return strconv.Itoa(*v)
}
