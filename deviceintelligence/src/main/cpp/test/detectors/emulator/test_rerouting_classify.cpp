// Host unit test for the pure INTEL_0047 classifier (rerouting_classify.cpp).
// Not built by gradle; compiled directly with host c++ (see
// tools/qa/native-unit-tests.sh). The classifier only uses <cstdint>, so it
// builds & runs on the host.
//
// The golden values below are the measured numbers from the spike
// (docs/spikes/cpu-rerouting.md): Pixel 6 Pro genuine silicon vs the arm64
// binary executed through libndk_translation on an x86_64 AVD.

#include "dicore/detectors/emulator/translation/rerouting_classify.h"

#include <cassert>
#include <cstdint>
#include <cstdio>

using namespace dicore;

namespace {

constexpr uint64_t kPixelFreq = 24'576'000;      // genuine Pixel 6 Pro CNTFRQ
constexpr uint64_t kWindow20Ms = 20'000'000;     // ns
constexpr uint64_t kGenuineTicks = 491'517;      // ~24.576 MHz * 20 ms
constexpr uint64_t kBridgeTicks = 48'383'693;    // host TSC ~2.42 GHz * 20 ms
constexpr uint64_t kBridgeFreq = 10'485'760;     // synthesized CNTFRQ

}  // namespace

int main() {
    // -- genuine silicon: no finding ----------------------------------------
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, kGenuineTicks, kWindow20Ms,
            true, emu::kIllIllopc, true);
        assert(!f.affirmative && !f.counter_incoherent && !f.counter_frozen &&
               !f.fault_breach);
        assert(f.counter_hz > 0 && f.udf_si_code == emu::kIllIllopc);
    }

    // genuine silicon, sub-tick jitter on the wall clock: still clean
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, kGenuineTicks - 3, kWindow20Ms,
            true, emu::kIllIllopc, true);
        assert(!f.affirmative);
    }

    // -- translated environment (measured): counter runs at the host rate ----
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kBridgeFreq, true, kBridgeTicks, kWindow20Ms,
            true, -1 /* SI_USER */, true);
        assert(f.affirmative && f.counter_incoherent && f.fault_breach);
        assert(!f.counter_frozen);
        assert(f.counter_hz > 2'000'000'000ULL);  // host-rate, not declared
    }

    // counter alone must carry a finding (a bridge that fixes fault replay
    // but not the clock, and vice versa, still fires)
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kBridgeFreq, true, kBridgeTicks, kWindow20Ms,
            true, emu::kIllIllopc, true);
        assert(f.affirmative && f.counter_incoherent && !f.fault_breach);
    }
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, kGenuineTicks, kWindow20Ms,
            true, -1, true);
        assert(f.affirmative && f.fault_breach && !f.counter_incoherent);
    }

    // -- frozen / backwards counter ------------------------------------------
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, 0, kWindow20Ms, true, emu::kIllIllopc, false);
        assert(f.affirmative && f.counter_frozen && !f.counter_incoherent);
    }

    // -- tolerance boundary ---------------------------------------------------
    // just inside +1%: clean
    {
        const uint64_t hz_limit = kPixelFreq + kPixelFreq / 100;
        const uint64_t ticks = hz_limit * kWindow20Ms / 1'000'000'000ULL;
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, ticks, kWindow20Ms,
            true, emu::kIllIllopc, true);
        assert(!f.affirmative);
    }
    // clearly outside on the slow side: incoherent (a translator that divides
    // its host clock to fake a plausible CNTFRQ but overshoots down)
    {
        const uint64_t slow_ticks = kGenuineTicks / 2;
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, slow_ticks, kWindow20Ms,
            true, emu::kIllIllopc, true);
        assert(f.affirmative && f.counter_incoherent);
    }

    // -- fail-open: every missing input disables its sub-fact ----------------
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            false, 0, true, kBridgeTicks, kWindow20Ms, false, 0, false);
        assert(!f.affirmative);
    }
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, false, kBridgeTicks, 0, false, 0, false);
        assert(!f.affirmative);
    }
    {
        // zero declared frequency cannot anchor the rate check
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, 0, true, kBridgeTicks, kWindow20Ms, false, 0, false);
        assert(!f.affirmative);
    }

    // -- absurd tick count within a ms-scale window: incoherent ---------------
    {
        emu::ReroutingFinding f = emu::classify_rerouting(
            true, kPixelFreq, true, ~0ULL, kWindow20Ms,
            true, emu::kIllIllopc, true);
        assert(f.affirmative && f.counter_incoherent);
    }

    printf("ok: rerouting classifier matches the spike's golden values\n");
    return 0;
}
