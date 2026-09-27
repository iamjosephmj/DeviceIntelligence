package policy

// Policy — server-side false-positive tuning that lives OFF the device.
type Policy struct {
	BlockSeverities       []string
	Allow                 []string
	Block                 []string
	RequireStrongBox      bool
	MaxPatchAgeDays       int
	ObserveUnconfirmedRWX bool
}

func DefaultPolicy() Policy {
	return Policy{
		BlockSeverities: []string{"CRITICAL"},
		MaxPatchAgeDays: 365,
	}
}

// IsBlocking — the single blocking decision. Order is normative:
//  1. allow-list wins over everything
//  2. block-list wins over severity
//  3. a CONFIRMED RWX hook pool always blocks
//  4. opting into observe-unconfirmed-RWX downgrades a BARE RWX finding
//  5. otherwise the severity table decides
func (p Policy) IsBlocking(id, severity, kind string, hookStubRegions int, hasHookStubRegions bool) bool {
	if id != "" && contains(p.Allow, id) {
		return false
	}
	if id != "" && contains(p.Block, id) {
		return true
	}
	if kind == "rwx_memory_mapping" {
		if hookStubRegions > 0 {
			return true
		}
		if p.ObserveUnconfirmedRWX {
			return false
		}
	}
	return contains(p.BlockSeverities, upper(severity))
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}
