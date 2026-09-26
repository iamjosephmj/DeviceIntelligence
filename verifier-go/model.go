package verifier

// Decision — the layered verdict. REJECT: authenticity failed (not a genuine,
// fresh binding). COMPROMISED: genuine, but the device (or a signal) is
// compromised. TRUSTWORTHY: all three layers cleared.
type Decision string

const (
	DecisionTrustworthy Decision = "TRUSTWORTHY"
	DecisionCompromised Decision = "COMPROMISED"
	DecisionReject      Decision = "REJECT"
)

type CheckKind string

const (
	CheckKindAuth      CheckKind = "AUTH"
	CheckKindIntegrity CheckKind = "INTEGRITY"
)

type Check struct {
	Name   string
	OK     bool
	Detail string
	Kind   CheckKind
}

type DeviceInfo struct {
	API   *int
	ABI   string
	Model string
}

// ResolvedSignal — the opaque INTEL_ code plus registry metadata and the
// policy verdict. Only ID, Severity and Detail come from the device.
type ResolvedSignal struct {
	ID         string
	Detector   string
	Kind       string
	Title      string
	Severity   string
	Detail     string
	Blocking   bool
	Attributes map[string]string
}

// VerificationResult — the layered verdict with its full evidence ledger.
type VerificationResult struct {
	Decision          Decision
	Authentic         bool
	DeviceIntegrityOK bool
	Checks            []Check
	SchemaVersion     int
	Point             string
	TS                int64
	Nonce             string
	Device            *DeviceInfo
	Signals           []ResolvedSignal
}
