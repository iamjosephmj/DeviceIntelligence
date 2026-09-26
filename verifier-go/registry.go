package verifier

import (
	_ "embed"
	"encoding/json"
)

// SignalMeta — one row of the signal taxonomy.
type SignalMeta struct {
	ID       string `json:"id"`
	Detector string `json:"detector"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

// SignalRegistry — the signal taxonomy: opaque INTEL_ codes resolved to their
// meaning. The device never ships detector/kind — only the backend holds the
// table, so a code is meaningful only against THIS registry.
type SignalRegistry struct {
	byID map[string]SignalMeta
}

//go:embed resources/signals-registry.json
var signalsRegistryJSON string

// BundledRegistry loads the active rows from the embedded taxonomy.
func BundledRegistry() (SignalRegistry, error) {
	return RegistryFromJSON(signalsRegistryJSON)
}

func RegistryFromJSON(text string) (SignalRegistry, error) {
	var root struct {
		Signals []struct {
			ID       string `json:"id"`
			Detector string `json:"detector"`
			Kind     string `json:"kind"`
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Status   string `json:"status"`
		} `json:"signals"`
	}
	if err := json.Unmarshal([]byte(text), &root); err != nil {
		return SignalRegistry{}, err
	}
	byID := make(map[string]SignalMeta)
	for _, row := range root.Signals {
		if row.Status == "retired" {
			continue
		}
		d, k, s, t := row.Detector, row.Kind, row.Severity, row.Title
		if d == "" {
			d = "?"
		}
		if k == "" {
			k = "?"
		}
		byID[row.ID] = SignalMeta{ID: row.ID, Detector: d, Kind: k, Severity: s, Title: t}
	}
	return SignalRegistry{byID: byID}, nil
}

// Get is nil-safe: unknown codes, empty ids — nil back.
func (r SignalRegistry) Get(id string) (SignalMeta, bool) {
	m, ok := r.byID[id]
	return m, ok
}

func (r SignalRegistry) Size() int { return len(r.byID) }
