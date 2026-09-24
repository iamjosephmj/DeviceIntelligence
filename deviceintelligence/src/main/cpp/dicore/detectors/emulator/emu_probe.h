// emu_probe.h — CPU-instruction emulator probe API.
//
// Two ABI-specific implementations (emu_probe_arm64.cpp,
// emu_probe_x86_64.cpp) satisfy the same `probe()` contract; CMake
// links exactly one of them per ABI build.
//
// The probe reads CPU identity / hypervisor signals that QEMU/KVM
// can't trivially fake without a custom kernel:
//   - On AArch64: CNTFRQ_EL0, MIDR_EL1, REVIDR_EL1, ID_AA64ISAR0_EL1.
//   - On x86_64:  CPUID.1:ECX[31] (hypervisor present) and
//                 CPUID.0x40000000 (hypervisor vendor string).
//
// Output is a small POD: a verdict bit (`decisive`) the Kotlin side
// can branch on, plus a human-readable `raw` string for UI / telemetry
// containing every probed value so a maintainer can post-mortem a
// false-positive without re-running the probe.

#ifndef DICORE_EMU_PROBE_H_
#define DICORE_EMU_PROBE_H_

#include <cstddef>

namespace dicore::emu {

struct Signals {
    // True if any single signal triggered. Useful for telemetry but
    // NOT used for the verdict — some signals (e.g. CTR_EL0 echo)
    // alone are not enough to flip the runtime.emulator result.
    bool present;

    // True iff the probe is confident enough to fold into runtime.emulator as a
    // Tampered verdict. See decision-rule notes inline in each
    // implementation.
    bool decisive;

    // Human-readable "k=v|k=v|..." dump. Bounded so we never heap-
    // allocate from the probe; if the probe finds more facts than
    // fit, the trailing ones are dropped (the decisive bit doesn't
    // depend on the textual dump).
    char raw[192];
};

// Synchronous; safe to call from any thread; idempotent (the probe
// reads only architectural state). Cost is sub-microsecond on real
// silicon (a handful of register reads); on emulators it's similar.
Signals probe();

}  // namespace dicore::emu

#endif  // DICORE_EMU_PROBE_H_
