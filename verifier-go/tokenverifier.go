package verifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// The v1-era verify flow (TokenVerifier.kt port): authenticity + TEE facts.
// Layered like every port: AUTH failures => REJECT, INTEGRITY failures =>
// COMPROMISED, blocking signals => COMPROMISED, else TRUSTWORTHY.

type TokenVerifier struct {
	registry    SignalRegistry
	policy      Policy
	pinnedRoots []*x509.Certificate
}

func NewTokenVerifier(registry SignalRegistry, policy Policy,
	pinnedRoots []*x509.Certificate) TokenVerifier {
	return TokenVerifier{registry: registry, policy: policy, pinnedRoots: pinnedRoots}
}

// NewTokenVerifierBundled uses the embedded registry and pinned roots.
func NewTokenVerifierBundled() (TokenVerifier, error) {
	registry, err := BundledRegistry()
	if err != nil {
		return TokenVerifier{}, err
	}
	roots, err := DefaultPinnedRoots()
	if err != nil {
		return TokenVerifier{}, err
	}
	return NewTokenVerifier(registry, DefaultPolicy(), roots), nil
}

// checks — the ledger. Gates record under their layer; the two layer verdicts
// fall out of the ledger.
type checks struct{ all []Check }

func (c *checks) auth(name string, ok bool, detail string) bool {
	c.all = append(c.all, Check{Name: name, OK: ok, Detail: detail, Kind: CheckKindAuth})
	return ok
}

func (c *checks) integ(name string, ok bool, detail string) bool {
	c.all = append(c.all, Check{Name: name, OK: ok, Detail: detail, Kind: CheckKindIntegrity})
	return ok
}

func (c *checks) authentic() bool {
	for _, ck := range c.all {
		if ck.Kind == CheckKindAuth && !ck.OK {
			return false
		}
	}
	return true
}

func (c *checks) deviceIntegrityOK() bool {
	for _, ck := range c.all {
		if ck.Kind == CheckKindIntegrity && !ck.OK {
			return false
		}
	}
	return true
}

func (c *checks) toList() []Check { return append([]Check(nil), c.all...) }

func (v TokenVerifier) Verify(tokenHex, issuedNonce string) (VerificationResult, error) {
	checks := &checks{}

	text, err := KeystreamDecryptHex(tokenHex)
	if err != nil {
		return VerificationResult{}, err
	}
	sep := strings.Index(text, BindingSep)
	hasBinding := sep >= 0
	signed := text
	binding := ""
	if hasBinding {
		signed = text[:sep]
		binding = text[sep+len(BindingSep):]
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(signed), &doc)

	if !checks.auth("binding present", hasBinding,
		ternaryStr(hasBinding, "", "unbound/legacy token")) {
		return v.result(checks, doc), nil
	}
	if len(doc) == 0 {
		checks.auth("signed content is JSON", false, "unparseable signed_content")
		return v.result(checks, doc), nil
	}

	tokenNonce := jsonString(doc["nonce"])
	checks.auth("nonce matches issued", tokenNonce == issuedNonce, "")

	sigHex, certsHex := parseBinding(binding)
	if !checks.auth("chain + signature present", sigHex != "" && len(certsHex) > 0, "") {
		return v.result(checks, doc), nil
	}

	chain, err := ParseChain(certsHex)
	if err != nil || len(chain) == 0 {
		checks.auth("chain parses", false, "could not parse cert chain")
		return v.result(checks, doc), nil
	}
	leaf := chain[0]

	if root, rootErr := VerifyToPinnedRoot(chain, v.pinnedRoots); rootErr == nil {
		checks.auth("chain -> pinned Google root", true, root.Subject.String())
	} else {
		checks.auth("chain -> pinned Google root", false, rootErr.Error())
	}

	chal, chalErr := AttestationChallenge(leaf)
	checks.auth("attestation challenge == nonce",
		chalErr == nil && hex.EncodeToString(chal) == strings.ToLower(issuedNonce), "")

	sigOK := false
	if pub, ok := leaf.PublicKey.(*ecdsa.PublicKey); ok {
		if sig, sigErr := decodeHex(sigHex); sigErr == nil {
			digest := sha256.Sum256([]byte(signed))
			sigOK = ecdsa.VerifyASN1(pub, digest[:], sig)
		}
	}
	checks.auth("signature over verdict", sigOK,
		ternaryStr(sigOK, "", "ECDSA verify failed"))

	// Device-integrity layer — the TEE's own attestation fields.
	fields, fieldsErr := AttestationFieldsOf(leaf)
	secOK := fieldsErr == nil && fields != nil &&
		(fields.SecurityLevel != nil && (*fields.SecurityLevel == 1 || *fields.SecurityLevel == 2))
	checks.integ("hardware security level >= TEE", secOK,
		fieldsDetail(fields, fieldsErr, SecurityLevelName(fieldsInt(fields))))
	bootOK := fieldsErr == nil && fields != nil &&
		(fields.VerifiedBootState != nil && *fields.VerifiedBootState == 0)
	checks.integ("verified boot state = Verified", bootOK,
		fieldsDetail(fields, fieldsErr, BootStateName(bootStateInt(fields))))
	lockOK := fieldsErr == nil && fields != nil &&
		(fields.DeviceLocked != nil && *fields.DeviceLocked)
	checks.integ("device locked", lockOK,
		fieldsDetail(fields, fieldsErr, lockedName(fields)))

	return v.result(checks, doc), nil
}

func (v TokenVerifier) result(checks *checks, doc map[string]any) VerificationResult {
	authentic := checks.authentic()
	deviceOK := checks.deviceIntegrityOK()
	signals := resolveSignals(doc, v.registry, v.policy)
	blocking := false
	for _, s := range signals {
		if s.Blocking {
			blocking = true
			break
		}
	}
	var decision Decision
	switch {
	case !authentic:
		decision = DecisionReject
	case !deviceOK || blocking:
		decision = DecisionCompromised
	default:
		decision = DecisionTrustworthy
	}
	return VerificationResult{
		Decision: decision, Authentic: authentic, DeviceIntegrityOK: deviceOK,
		Checks: checks.toList(), SchemaVersion: jsonInt(doc["schemaVersion"]),
		Point: jsonString(doc["point"]), TS: int64(jsonInt(doc["ts"])),
		Nonce: jsonString(doc["nonce"]), Device: resolveDevice(doc),
		Signals: signals,
	}
}

func parseBinding(binding string) (string, []string) {
	sigHex := ""
	certsHex := []string{}
	for _, line := range splitLines(binding) {
		if strings.HasPrefix(line, "SIG\x1F") {
			sigHex = line[4:]
		} else if strings.HasPrefix(line, "CERT\x1F") {
			certsHex = append(certsHex, line[5:])
		}
	}
	return sigHex, certsHex
}

func fieldsInt(f *AttestationFields) *int {
	if f == nil {
		return nil
	}
	return f.SecurityLevel
}

func bootStateInt(f *AttestationFields) *int {
	if f == nil {
		return nil
	}
	return f.VerifiedBootState
}

func lockedName(f *AttestationFields) string {
	if f == nil || f.DeviceLocked == nil {
		return "parse error"
	}
	if *f.DeviceLocked {
		return "true"
	}
	return "false"
}

func fieldsDetail(f *AttestationFields, err error, name string) string {
	if err != nil || f == nil {
		return "parse error"
	}
	return name
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
