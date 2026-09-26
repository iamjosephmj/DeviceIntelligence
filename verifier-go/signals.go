package verifier

import "strings"

// Signal resolution: turn the device's opaque findings into registry-backed
// ResolvedSignals, and correlate structural + behavioral hook evidence.

// The detail tokens a backend may enrich with (space-separated k=v pairs).
var attrKeys = map[string]bool{
	"path": true, "module_id": true, "needed": true, "links_hook_lib": true,
	"hooked_symbol": true, "hooked_by": true, "target": true,
	"ondisk_confirmed": true, "on_disk_prologue": true, "trampoline_class": true,
	"object": true, "base": true, "seals": true, "key": true, "get": true,
	"area": true, "hook_stub_regions": true, "region_count": true,
}

func parseAttrs(detail string) map[string]string {
	attrs := map[string]string{}
	if detail == "" {
		return attrs
	}
	for _, tok := range strings.Split(detail, " ") {
		eq := strings.Index(tok, "=")
		if eq <= 0 {
			continue
		}
		k := tok[:eq]
		if attrKeys[k] {
			attrs[k] = tok[eq+1:]
		}
	}
	return attrs
}

func resolveSignals(doc map[string]any, registry SignalRegistry, policy Policy) []ResolvedSignal {
	raw, _ := doc["signals"].([]any)
	out := make([]ResolvedSignal, 0, len(raw))
	for _, item := range raw {
		s, _ := item.(map[string]any)
		if s == nil {
			continue
		}
		rawID, _ := s["id"].(string)
		if rawID == "" {
			rawID = "INTEL_UNKNOWN"
		}
		// Legacy SIG_-prefixed ids normalize before lookup.
		id := rawID
		if strings.HasPrefix(rawID, "SIG_") {
			id = "INTEL_" + rawID[4:]
		}
		meta, metaOK := registry.Get(id)
		detail, _ := s["detail"].(string)
		severity, _ := s["severity"].(string)
		if severity == "" && metaOK {
			severity = meta.Severity
		}
		attrs := parseAttrs(detail)
		stubs, hasStubs := 0, false
		if v, ok := attrs["hook_stub_regions"]; ok {
			stubs, hasStubs = atoi(v)
		}
		kind := "?"
		detector := "?"
		if metaOK {
			kind, detector = meta.Kind, meta.Detector
		}
		out = append(out, ResolvedSignal{
			ID: id, Detector: detector, Kind: kind,
			Title: metaTitle(meta), Severity: severity, Detail: detail,
			Blocking:   policy.IsBlocking(id, severity, kind, stubs, hasStubs),
			Attributes: attrs,
		})
	}
	return out
}

func metaTitle(meta SignalMeta) string {
	if meta == (SignalMeta{}) || meta.Title == "" {
		if meta.Title == "" {
			return ""
		}
	}
	return meta.Title
}

func atoi(v string) (int, bool) {
	n := 0
	neg := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}

func resolveDevice(doc map[string]any) *DeviceInfo {
	d, _ := doc["device"].(map[string]any)
	if d == nil {
		return nil
	}
	info := &DeviceInfo{}
	if api, ok := d["api"].(float64); ok {
		a := int(api)
		info.API = &a
	}
	info.ABI, _ = d["abi"].(string)
	info.Model, _ = d["model"].(string)
	return info
}

// DefinitiveHooks — the SAME symbol seen both structurally (inline hook /
// stub) and behaviorally (syscall divergence). Sorted for determinism.
func definitiveHooks(signals []ResolvedSignal) []string {
	structural := map[string]bool{}
	behavioral := map[string]bool{}
	for _, s := range signals {
		switch s.Kind {
		case "libc_inline_hook", "libc_inline_stub":
			if sym := s.Attributes["hooked_symbol"]; sym != "" {
				structural[sym] = true
			}
		case "syscall_divergence":
			if sym := s.Attributes["hooked_symbol"]; sym != "" {
				behavioral[sym] = true
			}
		}
	}
	out := []string{}
	for sym := range structural {
		if behavioral[sym] {
			out = append(out, sym)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
