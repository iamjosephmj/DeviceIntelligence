#pragma once

// Pure classifier: is THIS PROCESS's CPU being rerouted by a binary-
// translation layer, judged from measurements the process takes on itself?
//
// Companion to translation_classify.h (INTEL_0027), which keys on names and
// provenance. This one keys on *behaviour* — the two seams a CPU-virtualizing
// layer cannot close without breaking the translation (spike:
// docs/spikes/cpu-rerouting.md, measured 2026-09-11):
//
//   1. Counter coherence. On real ARMv8 silicon CNTVCT_EL0 advances at
//      exactly CNTFRQ_EL0 — the generic timer is a fixed always-on clock
//      domain that does not track DVFS, so there is no legitimate rate
//      mismatch (measured error on a Pixel 6 Pro: 0.0000). A translation
//      layer has no guest architectural timer to read; it serves CNTVCT from
//      the host clock (measured on libndk_translation: counter running
//      23,000x its declared frequency).
//   2. Synchronous-fault fidelity. A permanently-undefined instruction
//      executed by this process always reports SIGILL si_code=ILL_ILLOPC on
//      a genuine AArch64 kernel. A bridge replays the fault from its own
//      metadata as if it had been SENT — measured si_code=SI_USER, which a
//      synchronous instruction fault cannot carry on real hardware. A
//      translator that swallows the fault entirely breaches the same way
//      (no ILL_ILLOPC report exists).
//
// Everything here is pure arithmetic over probe-supplied measurements:
// host-testable (test/detectors/emulator/). Missing or unreadable inputs
// contribute nothing — fail-open, never a guess. The SUPPORTING probes from
// the spike (syscall toll, cold-vs-warm translation tax, hwcap shape) are
// deliberately absent: their populations straddle across devices, so they
// must never gate a finding.

#include <cstdint>

namespace dicore {
namespace emu {

struct ReroutingFinding {
    bool affirmative = false;         // any sub-fact fired -> emit a record
    bool counter_incoherent = false;  // CNTVCT rate diverges from CNTFRQ
    bool counter_frozen = false;      // CNTVCT did not advance (or went backwards)
    bool fault_breach = false;        // UDF fault not reported as ILL_ILLOPC

    // Echoes for the record detail (evidence, never gating).
    uint64_t counter_freq = 0;  // CNTFRQ_EL0 as read (Hz)
    uint64_t counter_hz = 0;    // measured CNTVCT advance rate (Hz)
    int udf_si_code = 0;        // si_code observed for the undefined instruction
    bool udf_addr_match = false;  // si_addr == reported PC (echo only; the
                                  // spike showed bridges match the address
                                  // even when they lie about provenance)
};

// ILL_ILLOPC — the only si_code a synchronous undefined-instruction fault
// can carry on a genuine AArch64 Linux kernel.
constexpr int kIllIllopc = 1;

// Rate tolerance, in percent. Genuine silicon measures 0.0000 error; 1% is
// ~3800x above observed genuine noise and still ~200x below the closest
// plausible synthesized counter.
constexpr uint64_t kRateTolerancePct = 1;

// The classifier proper. All inputs are probe-supplied; every `have_*` false
// silently disables that sub-fact.
//   counter_ticks: CNTVCT delta across the probe window (0 = frozen)
//   window_ns:     the window's CLOCK_MONOTONIC length in ns (0 -> fail open)
//   udf_si_code:   si_code captured for the undefined instruction (0 when the
//                  instruction did not fault at all — also a breach)
ReroutingFinding classify_rerouting(bool have_freq, uint64_t counter_freq,
                                    bool have_window, uint64_t counter_ticks,
                                    uint64_t window_ns, bool have_fault,
                                    int udf_si_code, bool udf_addr_match);

}  // namespace emu
}  // namespace dicore
