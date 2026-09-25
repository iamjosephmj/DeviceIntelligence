// rerouting_probe.cpp — device-side probe for INTEL_0047
// (cpu_rerouting_anomaly). See rerouting_classify.h for the classification
// contract; this TU takes the two measurements and emits the record.
//
// Measurement notes, per family convention:
//   - CNTFRQ_EL0 / CNTVCT_EL0 are read with MRS, wrapped in the house
//     sigsetjmp/SIGILL guard (a kernel with MRS emulation disabled traps the
//     read; a trapped read means the counter sub-fact contributes nothing).
//   - The rate window is CLOCK_MONOTONIC around a 20 ms sleep — wall-clock
//     time, not instruction time, so the comparison is between two clocks a
//     translator must serve *both* of, coherently, to stay invisible.
//   - arm64-only by construction: on every other ABI the record function is
//     empty (the probes read registers the other ISAs do not have — this is
//     the emu_probe_{arm64,generic} split, collapsed into one TU because the
//     generic side is simply "no records").
// Every failure path contributes nothing. Fail-open; no finding without an
// affirmative sub-fact.

#include "dicore/detectors/emulator/translation/rerouting_classify.h"
#include "dicore/platform/obf.h"

#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#if defined(__aarch64__)

namespace dicore {

namespace {

sigjmp_buf g_udf_return;
volatile sig_atomic_t g_udf_si_code = 0;
uintptr_t g_udf_si_addr = 0;
uintptr_t g_udf_pc = 0;

void udf_sigill_handler(int /*sig*/, siginfo_t* info, void* uctx) {
    g_udf_si_code = info ? info->si_code : -1;
    g_udf_si_addr = info ? reinterpret_cast<uintptr_t>(info->si_addr) : 0;
    if (uctx) {
        auto* uc = reinterpret_cast<ucontext_t*>(uctx);
        g_udf_pc = uc->uc_mcontext.pc;
    }
    siglongjmp(g_udf_return, 1);
}

// MRS is read-only at EL0 but can still be trapped by a hardened kernel;
// guard every read with the SIGILL longjmp (same shape as the SAFE_MRS macro
// in emu_probe_arm64.cpp — kept local so the two probes evolve separately).
#define REROUTE_MRS(out_var, reg_literal) ({                                   \
    bool _ok = false;                                                          \
    struct sigaction _old{};                                                   \
    struct sigaction _new{};                                                   \
    _new.sa_sigaction = udf_sigill_handler;                                    \
    _new.sa_flags = SA_SIGINFO;                                                \
    sigemptyset(&_new.sa_mask);                                                \
    sigaction(SIGILL, &_new, &_old);                                           \
    if (sigsetjmp(g_udf_return, 1) == 0) {                                     \
        uint64_t _tmp = 0;                                                     \
        __asm__ volatile("mrs %0, " reg_literal : "=r"(_tmp));                 \
        (out_var) = _tmp;                                                      \
        _ok = true;                                                            \
    }                                                                          \
    sigaction(SIGILL, &_old, nullptr);                                         \
    _ok;                                                                       \
})

inline uint64_t cntvct_now() {
    uint64_t v;
    __asm__ volatile("mrs %0, CNTVCT_EL0" : "=r"(v));
    return v;
}

constexpr uint64_t kWindowNs = 20'000'000;  // 20 ms

}  // namespace

std::vector<std::string> emu_rerouting_records() {
    constexpr char kFS = '\x1f';

    // -- counter coherence ---------------------------------------------------
    uint64_t freq = 0;
    bool have_freq = REROUTE_MRS(freq, "CNTFRQ_EL0");

    struct timespec t0{};
    struct timespec t1{};
    uint64_t ticks = 0;
    uint64_t window_ns = 0;
    bool have_window = false;
    if (clock_gettime(CLOCK_MONOTONIC, &t0) == 0) {
        const uint64_t c0 = cntvct_now();
        struct timespec req{0, static_cast<long>(kWindowNs)};
        nanosleep(&req, nullptr);
        if (clock_gettime(CLOCK_MONOTONIC, &t1) == 0) {
            const uint64_t c1 = cntvct_now();
            if (t1.tv_nsec >= t0.tv_nsec || t1.tv_sec > t0.tv_sec) {
                window_ns =
                    static_cast<uint64_t>(t1.tv_sec - t0.tv_sec) * 1'000'000'000ULL +
                    static_cast<uint64_t>(t1.tv_nsec) -
                    static_cast<uint64_t>(t0.tv_nsec);
            }
            // a counter that moved backwards reads as frozen (0); both are
            // incoherent on genuine silicon
            ticks = c1 > c0 ? c1 - c0 : 0;
            have_window = window_ns > 0;
        }
    }

    // -- synchronous-fault fidelity -------------------------------------------
    int udf_si_code = 0;
    bool udf_addr_match = false;
    {
        struct sigaction old{};
        struct sigaction sa{};
        sa.sa_sigaction = udf_sigill_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGILL, &sa, &old);
        g_udf_si_code = 0;
        g_udf_si_addr = 0;
        g_udf_pc = 0;
        if (sigsetjmp(g_udf_return, 1) == 0) {
            goto udf_site;  // NOLINT
        udf_site:
            __asm__ volatile(".inst 0x00000000");  // permanently undefined
        } else {
            udf_si_code = static_cast<int>(g_udf_si_code);
            udf_addr_match = g_udf_pc != 0 && g_udf_si_addr == g_udf_pc;
        }
        sigaction(SIGILL, &old, nullptr);
    }

    emu::ReroutingFinding f = emu::classify_rerouting(
        have_freq, freq, have_window, ticks, window_ns, /*have_fault=*/true,
        udf_si_code, udf_addr_match);
    if (!f.affirmative) return {};

    // kind \x1f SEVERITY \x1f k=v|k=v...
    std::string r = "cpu_rerouting_anomaly";
    r += kFS;
    r += "CRITICAL";
    r += kFS;
    r += "cntfrq=";
    r += std::to_string(freq);
    r += "|have_freq=";
    r += have_freq ? "1" : "0";
    r += "|ticks=";
    r += std::to_string(ticks);
    r += "|window_ns=";
    r += std::to_string(window_ns);
    if (f.counter_frozen) r += "|frozen=1";
    if (f.udf_si_code != emu::kIllIllopc) {
        r += "|udf_code=";
        r += std::to_string(f.udf_si_code);
    }
    return {r};
}

}  // namespace dicore

#else  // !__aarch64__

namespace dicore {

// The rerouting probes read arm64 system registers — on every other ABI the
// record function is empty (the probes read registers the other ISAs do not
// have). Fail-open: contributes nothing rather than guessing.
std::vector<std::string> emu_rerouting_records() {
    return {};
}

}  // namespace dicore

#endif  // __aarch64__
