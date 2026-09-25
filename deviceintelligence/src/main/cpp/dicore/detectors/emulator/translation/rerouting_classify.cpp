// rerouting_classify.cpp — pure verdict logic for INTEL_0047
// (cpu_rerouting_anomaly). See rerouting_classify.h for the contract and
// docs/spikes/cpu-rerouting.md for the measured evidence behind each rule.

#include "dicore/detectors/emulator/translation/rerouting_classify.h"

namespace dicore {
namespace emu {

ReroutingFinding classify_rerouting(bool have_freq, uint64_t counter_freq,
                                    bool have_window, uint64_t counter_ticks,
                                    uint64_t window_ns, bool have_fault,
                                    int udf_si_code, bool udf_addr_match) {
    ReroutingFinding f;
    f.counter_freq = counter_freq;
    f.udf_si_code = udf_si_code;
    f.udf_addr_match = udf_addr_match;

    // -- counter coherence --------------------------------------------------
    // Needs both anchors: the declared frequency and a timed window. Anything
    // missing or degenerate contributes nothing.
    if (have_freq && have_window && counter_freq > 0 && window_ns > 0) {
        if (counter_ticks == 0) {
            // A 24.576 MHz counter cannot sit still across a multi-ms window;
            // frozen (or wrapped backwards, which the probe also reports as 0)
            // is as incoherent as running fast.
            f.counter_frozen = true;
        } else if (counter_ticks <= UINT64_MAX / 1'000'000'000ULL) {
            f.counter_hz = counter_ticks * 1'000'000'000ULL / window_ns;
            const uint64_t band = counter_freq / 100 * kRateTolerancePct;
            if (f.counter_hz > counter_freq + band ||
                f.counter_hz + band < counter_freq) {
                f.counter_incoherent = true;
            }
        } else {
            // More than ~1.8e10 ticks in a millisecond-scale window is not a
            // counter, it is an address; no genuine silicon does this.
            f.counter_incoherent = true;
        }
    }

    // -- synchronous-fault fidelity ------------------------------------------
    // have_fault is "the UDF test ran to completion", not "it faulted": a
    // translator that swallows the instruction leaves udf_si_code == 0, which
    // breaches exactly like a replayed SI_USER report.
    if (have_fault && udf_si_code != kIllIllopc) {
        f.fault_breach = true;
    }

    f.affirmative = f.counter_incoherent || f.counter_frozen || f.fault_breach;
    return f;
}

}  // namespace emu
}  // namespace dicore
