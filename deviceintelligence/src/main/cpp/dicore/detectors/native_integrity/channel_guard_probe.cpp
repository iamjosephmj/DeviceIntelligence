// channel_guard_probe.cpp — native_integrity probe for INTEL_0029
// (channel_sequence_anomaly). See channel_guard.hpp for the chain contract;
// this TU advances the chain once per scan and enforces the on-device rate
// guard. Runs at scan entry (dicore_verdict → here), so the counter is the
// scan channel's monotonic position.
//
// SESSION-KEY BINDING (deliberate v1 deviation, recorded in the task report):
// the attested-session cache holds no SECRET session key on the native side —
// its "attested_key" is the hex SPKI of a PUBLIC key — so the chain is rooted
// at a process-local random key (crypto::secure_random, getrandom(2)), derived
// once at first scan. Gaps/reuse/label-mismatch and MAC forgery of THIS
// process's channel are still caught on-device and by any replayed verifier
// state; what the random root cannot give is CROSS-DEVICE backend MAC
// verification. The token-crypto task binds the root to the session key when
// it becomes reachable at scan time; the binding point is this TU's g_key /
// seq_init call — swap the key source there and nothing else changes.

#include "dicore/core/verdict_cores.h"
#include "dicore/crypto/rand.h"
#include "dicore/detectors/native_integrity/channel_guard.hpp"
#include "dicore/platform/obf.h"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace dicore {

namespace {

// A user-driven flow issues a handful of scans per second at most (one per
// guarded request). The synthetic drive this guard exists for — the
// Incognia-style 60-command sweep — fires dozens within seconds, so 30 scans
// per 10 s window separates the two by an order of magnitude. The window is
// SLIDING (see rate_allow); a patient attacker spacing scans >10 s apart is
// not a sweep and is the backend's replay problem, not this guard's.
constexpr int kRateWindowMs = 10'000;
constexpr int kRateMaxScans = 30;

// The label folded into every chain step. A replay of this channel's (counter,
// mac) pairs under any other label fails verification by construction.
constexpr char kScanLabel[] = "dicore_scan";

std::mutex g_mu;
bool g_init = false;
uint8_t g_key[32];
dicore::channel_guard::SeqState g_seq{};
dicore::channel_guard::RateGuard g_rate{};

void to_hex32(const uint8_t in[32], char out[65]) {
    static const char kH[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2] = kH[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = kH[in[i] & 0xF];
    }
    out[64] = 0;
}

}  // namespace

DI_OBF_ORCH
std::vector<std::string> channel_guard_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;

    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_init) {
        if (!crypto::secure_random(g_key, sizeof(g_key))) return {};   // fail-open
        dicore::channel_guard::seq_init(g_seq, g_key);
        dicore::channel_guard::rate_init(g_rate, kRateWindowMs, kRateMaxScans);
        g_init = true;
    }

    // Monotonic clock, same time base the orchestrator's rate-limited APK
    // re-hash uses (steady_clock in orchestrate.cpp) — wall-clock jumps must
    // not open or close the window.
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

    // Advance the chain EVERY scan, violation or not — the counter must count
    // scans, and the (counter, mac_chain) pair is the evidence a later token
    // binding carries (see the binding comment above).
    const uint64_t counter = dicore::channel_guard::seq_next(g_seq, g_key, kScanLabel);
    if (dicore::channel_guard::rate_allow(g_rate, now_ms)) return {};

    char mac[65];
    to_hex32(g_seq.mac_chain, mac);

    // kind \x1f SEVERITY \x1f k=v|k=v...
    std::string r = "channel_sequence_anomaly";
    r += kFS;
    r += "CRITICAL";
    r += kFS;
    r += "rate_exhausted=1";
    r += "|seq=" + std::to_string(counter);
    r += "|mac=";
    r += mac;
    r += "|rate_window_ms=" + std::to_string(kRateWindowMs);
    r += "|rate_max_scans=" + std::to_string(kRateMaxScans);
    out.push_back(r);
    return out;
}

}  // namespace dicore
