// watchdog_probe.cpp — native_integrity probe for INTEL_0018
// (watchdog_anomaly). See watchdog.hpp for the engine contract; this TU owns
// the ONE Android-flavored piece — the production Spawn (pipe + fork; the
// child dup2's the pipe onto stderr and execl's /system/bin/sh -c, the only
// async-signal-safe calls between fork and exec, so forking from a JVM
// thread is safe) — plus the dicore_verdict glue: lazy key, lazy start,
// per-scan poll, record building.
//
// KEY (v1, same recorded deviation as channel_guard_probe.cpp): rooted at a
// process-local random key (crypto::secure_random) because no SECRET session
// key is reachable natively at scan time. The (seq, mac) evidence pair still
// proves on-device freshness and anti-replay for THIS process's findings;
// cross-device backend verification arrives with the token-crypto rebind —
// swap g_key's source there and nothing else changes.
//
// Fail-open everywhere: secure_random failure, spawn failure (retried next
// scan), and every parse path inside the engine contribute no finding.
// Detection-only: the child is never killed and never respawned — a dead
// child's standing finding IS the report.
#include "dicore/core/verdict_cores.h"
#include "dicore/crypto/rand.h"
#include "dicore/detectors/native_integrity/watchdog.hpp"
#include "dicore/platform/obf.h"

#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace dicore {

namespace {

// Production Spawn: pipe, fork, child redirects stderr onto the pipe write
// end and execs the shell; parent keeps the read fd. Returns 0 with
// *pipe_out set, -1 on any failure (both fds closed).
int prod_spawn(const char* cmd, int* pipe_out) {
    int fds[2];
    if (pipe(fds) != 0) return -1;
    const pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        // Child. Only async-signal-safe calls until exec.
        close(fds[0]);
        if (dup2(fds[1], 2) < 0) _exit(127);
        if (fds[1] != 2) close(fds[1]);
        execl("/system/bin/sh", "sh", "-c", cmd, static_cast<char*>(nullptr));
        _exit(127);
    }
    close(fds[1]);
    *pipe_out = fds[0];
    return 0;
}

std::mutex g_mu;
bool g_key_init = false;
uint8_t g_key[16];
dicore::watchdog::Monitor g_mon;

void to_hex8(const uint8_t in[8], char out[17]) {
    static const char kH[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        out[i * 2] = kH[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = kH[in[i] & 0xF];
    }
    out[16] = 0;
}

}  // namespace

DI_OBF_ORCH
std::vector<std::string> watchdog_records() {
    constexpr char kFS = '\x1f';
    std::vector<std::string> out;

    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_key_init) {
        if (!crypto::secure_random(g_key, sizeof(g_key))) return {};   // fail-open
        g_key_init = true;
    }
    // Idempotent; a failed spawn (e.g. transient fork pressure) is retried
    // on the next scan — never latched, never a finding.
    if (!dicore::watchdog::start(g_mon, g_key, prod_spawn)) return {};

    // Monotonic clock — same time base as the INTEL_0029 rate guard; wall-clock
    // jumps must not fabricate or mask missed beats.
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

    dicore::watchdog::poll_monitor(g_mon, now_ms);

    std::string cause;
    switch (dicore::watchdog::classify(g_mon, now_ms)) {
        case dicore::watchdog::Finding::kSilent:
            cause = "silent";
            break;
        case dicore::watchdog::Finding::kTracer:
            cause = "tracer";
            break;
        case dicore::watchdog::Finding::kNone:
            return {};
    }

    // Keyed-heartbeat evidence pair rides the record (INTEL_0029's shape):
    // fresh (seq, mac) per emitted finding, consume-once verifiable.
    dicore::watchdog::Heartbeat hb;
    dicore::watchdog::evidence(g_mon, hb);
    char mac[17];
    to_hex8(hb.hmac, mac);

    // kind \x1f SEVERITY \x1f k=v|k=v...
    std::string r = "watchdog_anomaly";
    r += kFS;
    r += "HIGH";
    r += kFS;
    r += "cause=" + cause;
    if (cause == "tracer") {
        r += "|tracer_pid=" + std::to_string(g_mon.tracer_pid);
    } else {
        r += "|missed=" + std::to_string(dicore::watchdog::missed_beats(
                                  g_mon.lv, now_ms, dicore::watchdog::kBeatPeriodMs));
    }
    r += "|seq=" + std::to_string(hb.seq);
    r += "|mac=";
    r += mac;
    r += "|period_ms=" + std::to_string(dicore::watchdog::kBeatPeriodMs);
    out.push_back(r);
    return out;
}

}  // namespace dicore
