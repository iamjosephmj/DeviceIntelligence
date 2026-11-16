package policy

import "testing"

func TestPolicyCriticalSeverityBlocks(t *testing.T) {
	if !DefaultPolicy().IsBlocking("INTEL_0001", "CRITICAL", "", 0, false) {
		t.Fatal("CRITICAL must block")
	}
}

func TestPolicyNonCriticalDoesNotBlockByDefault(t *testing.T) {
	p := DefaultPolicy()
	if p.IsBlocking("INTEL_0019", "HIGH", "", 0, false) {
		t.Fatal("HIGH must not block by default")
	}
	if p.IsBlocking("INTEL_0050", "MEDIUM", "", 0, false) {
		t.Fatal("MEDIUM must not block by default")
	}
}

func TestPolicyAllowListOverridesSeverity(t *testing.T) {
	p := DefaultPolicy()
	p.Allow = []string{"INTEL_0052"}
	if p.IsBlocking("INTEL_0052", "CRITICAL", "", 0, false) {
		t.Fatal("allow-list must win over severity")
	}
}

func TestPolicyBlockListOverridesSeverity(t *testing.T) {
	p := DefaultPolicy()
	p.Block = []string{"INTEL_0050"}
	if !p.IsBlocking("INTEL_0050", "MEDIUM", "", 0, false) {
		t.Fatal("block-list must win over severity")
	}
}

func TestPolicyAllowTakesPrecedenceOverBlock(t *testing.T) {
	p := DefaultPolicy()
	p.Allow = []string{"INTEL_0001"}
	p.Block = []string{"INTEL_0001"}
	if p.IsBlocking("INTEL_0001", "CRITICAL", "", 0, false) {
		t.Fatal("allow must take precedence over block")
	}
}

func TestPolicySeverityComparisonCaseInsensitive(t *testing.T) {
	if !DefaultPolicy().IsBlocking("", "critical", "", 0, false) {
		t.Fatal("case-insensitive severity match expected")
	}
}

func TestPolicyNullSeverityDoesNotBlock(t *testing.T) {
	if DefaultPolicy().IsBlocking("", "", "", 0, false) {
		t.Fatal("empty severity must not block")
	}
}

func TestPolicyConfirmedRwxHookPoolAlwaysBlocks(t *testing.T) {
	p := DefaultPolicy()
	p.ObserveUnconfirmedRWX = true
	if !p.IsBlocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 3, true) {
		t.Fatal("confirmed RWX pool must always block")
	}
}

func TestPolicyBareRwxDowngradesOnlyWhenOptedIn(t *testing.T) {
	if !DefaultPolicy().IsBlocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0, true) {
		t.Fatal("bare RWX under CRITICAL severity blocks by default")
	}
	if DefaultPolicy().IsBlocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0, true) ==
		!DefaultPolicy().IsBlocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0, true) {
		t.Fatal("unreachable")
	}
	p := DefaultPolicy()
	p.ObserveUnconfirmedRWX = true
	if p.IsBlocking("INTEL_0052", "CRITICAL", "rwx_memory_mapping", 0, true) {
		t.Fatal("opted-in downgrade must not block a bare RWX")
	}
}
