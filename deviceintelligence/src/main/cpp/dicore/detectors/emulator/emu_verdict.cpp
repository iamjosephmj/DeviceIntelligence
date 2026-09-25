// emu_verdict.cpp — runtime.emulator verdict core (CPU-identity probe).
//
// Wraps the ABI-specific dicore::emu::probe() (emu_probe_{arm64,x86_64,generic})
// in the orchestrator's US(0x1f)-framed Finding contract (see verdict_cores.h).
// A `decisive` probe — QEMU's signature generic-timer frequency on arm64, or the
// hypervisor-present bit AND a known hypervisor vendor string on x86_64 — produces a
// `runtime_emulator_cpu` record. A non-decisive probe emits nothing.
//
// !! NOT WIRED — and now unreachable by construction. emu_verdict_records() had exactly
// one caller, det_emulator() in orchestrator/collect.cpp, and that whole registry driver
// was deleted as dead code. dicore_verdict() (orchestrate.cpp) calls the *_records() functions
// directly and deliberately omits emulator ("REMOVED from the verdict (false-positive
// prone)"). There is also no `emulator` row in signals-registry.json, so a record from
// here would serialise as INTEL_UNKNOWN.
//
// An earlier version of this comment claimed "the orchestrator counts [it] toward the
// kill". It did not. Emulators are caught by the attestation layer instead: no hardware
// root of trust (INTEL_0056), a chain that does not reach a pinned Google root, and an
// unverified boot state.
//
// This core is retained but dead. See issue #8 before wiring or deleting it.

#include "dicore/detectors/emulator/emu_probe.h"
#include "dicore/core/verdict_cores.h"

#include <string>
#include <vector>

namespace dicore {

std::vector<std::string> emu_verdict_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;
    emu::Signals s = emu::probe();
    if (s.decisive) {
        // kind \x1f SEVERITY \x1f raw-signals
        out.push_back(std::string("runtime_emulator_cpu") + kFS + "CRITICAL" + kFS + s.raw);
    }
    return out;
}

}  // namespace dicore
