package verifier

import (
	"encoding/json"
	"strings"
)

// Decodes a token and returns its document WITHOUT verifying
// (TokenDecoder.kt port).
type TokenDecoder struct {
	registry SignalRegistry
	policy   Policy
}

func NewTokenDecoder(registry SignalRegistry, policy Policy) TokenDecoder {
	return TokenDecoder{registry: registry, policy: policy}
}

// The framing that matters below the envelope. Kept here because the decoder
// is the framing's owner; the verifier imports it from this package.
const BindingSep = "\n--BINDING\n"

type DecodedToken struct {
	SchemaVersion int
	Point         string
	TS            int64
	Nonce         string
	Device        *DeviceInfo
	Signals       []ResolvedSignal
	HasBinding    bool
}

func (d TokenDecoder) Decode(tokenHex string) (DecodedToken, error) {
	text, err := KeystreamDecryptHex(tokenHex)
	if err != nil {
		return DecodedToken{}, err
	}
	idx := strings.Index(text, BindingSep)
	signed := text
	hasBinding := idx >= 0
	if hasBinding {
		signed = text[:idx]
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(signed), &doc); err != nil {
		return DecodedToken{}, err
	}
	return DecodedToken{
		SchemaVersion: jsonInt(doc["schemaVersion"]),
		Point:         jsonString(doc["point"]),
		TS:            int64(jsonInt(doc["ts"])),
		Nonce:         jsonString(doc["nonce"]),
		Device:        resolveDevice(doc),
		Signals:       resolveSignals(doc, d.registry, d.policy),
		HasBinding:    hasBinding,
	}, nil
}

func jsonInt(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func jsonString(v any) string {
	s, _ := v.(string)
	return s
}
