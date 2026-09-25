// watchdog.cpp — INTEL_0018 watchdog engine (pure + pipe I/O, host-testable).
// See watchdog.hpp for the contract. The ONLY Android-flavored piece — the
// fork/dup2/execl production spawn — lives in watchdog_probe.cpp behind the
// Spawn indirection. Crypto is the vendored SHA-256 every other TU uses.
#include "dicore/detectors/native_integrity/watchdog.hpp"

#include "dicore/crypto/sha256.h"

#include <cstdio>
#include <cstring>
#include <poll.h>
#include <unistd.h>

namespace dicore::watchdog {
namespace {

// 'W','D','O','G' — fixed beat marker; any other magic is not our heartbeat.
constexpr uint32_t kMagic = 0x57444F47u;

// A beat line never exceeds this; a newline-less flood is dropped beyond it
// so hostile garbage cannot grow `pending` (and memory) unboundedly.
constexpr size_t kMaxPending = 8192;

void put_be32(uint8_t out[4], uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<uint8_t>(v >> (24 - 8 * i));
    }
}

bool is_ws(char c) { return c == ' ' || c == '\t' || c == '\r'; }

}  // namespace

void beat(uint32_t seq, const uint8_t key[16], Heartbeat& out) {
    out.magic = kMagic;
    out.seq = seq;
    // mac = SHA-256(key || be32(seq)) truncated to 8 bytes: the key is folded
    // in at every step, so a seen mac never reveals the next one.
    uint8_t buf[16 + 4];
    std::memcpy(buf, key, 16);
    put_be32(buf + 16, seq);
    uint8_t d[32];
    if (!dicore::sha::sha256(buf, sizeof buf, d)) {
        std::memset(out.hmac, 0, 8);   // backend down: no evidence (fail-open)
        return;
    }
    std::memcpy(out.hmac, d, 8);
}

bool check(const Heartbeat& hb, uint32_t expect_seq, const uint8_t key[16]) {
    // Validity gates before any hashing (channel_guard's seq_verify style):
    // seq 0 is the never-a-beat marker on both sides.
    if (expect_seq == 0 || hb.seq == 0) return false;

    Heartbeat want;
    beat(expect_seq, key, want);

    // One constant-time fold over magic, seq and ALL 8 mac bytes — no early
    // exit on the first differing byte.
    uint32_t diff = hb.magic ^ want.magic;
    diff |= hb.seq ^ want.seq;
    for (int i = 0; i < 8; ++i) {
        diff |= static_cast<uint32_t>(hb.hmac[i] ^ want.hmac[i]);
    }
    return diff == 0;
}

void liveness_init(Liveness& lv, int64_t now_ms) {
    lv.started_ms = now_ms;
    lv.last_beat_ms = 0;
}

void liveness_on_beat(Liveness& lv, int64_t now_ms) {
    lv.last_beat_ms = now_ms;
}

int missed_beats(const Liveness& lv, int64_t now_ms, int64_t period_ms) {
    if (period_ms <= 0) return 0;
    const int64_t anchor = lv.last_beat_ms != 0 ? lv.last_beat_ms : lv.started_ms;
    if (now_ms <= anchor) return 0;
    return static_cast<int>((now_ms - anchor) / period_ms);
}

bool parse_wd_line(const char* line, bool* has_tracer, uint32_t* tracer_pid) {
    if (has_tracer) *has_tracer = false;
    if (!line) return false;
    const char* p = line;
    while (is_ws(*p)) ++p;
    if (p[0] != 'W' || p[1] != 'D') return false;
    p += 2;
    if (*p == '\0') return true;              // bare "WD": beat, no tracer info
    if (!is_ws(*p)) return false;             // "WDx..." is not our marker
    while (is_ws(*p)) ++p;

    if (std::strncmp(p, "TracerPid:", 10) == 0) {
        p += 10;
        while (is_ws(*p)) ++p;
        if (!(*p >= '0' && *p <= '9')) return true;   // prefix, no digits: beat
        uint64_t v = 0;
        while (*p >= '0' && *p <= '9') {
            if (v < 0xFFFFFFFFull) v = v * 10 + (uint64_t)(*p - '0');
            ++p;
        }
        if (has_tracer) *has_tracer = true;
        if (tracer_pid) *tracer_pid = static_cast<uint32_t>(v);
        return true;
    }
    return true;                              // "WD <other>" is still a beat
}

bool start(Monitor& m, const uint8_t key[16], Spawn spawn_fn) {
    if (m.fd >= 0) return true;               // already running (idempotent)
    if (!spawn_fn) return false;

    // The child re-reads OUR status from ITS independent process. sleep must
    // equal kBeatPeriodMs/1000 — the classifier's window is defined by it.
    char cmd[160];
    std::snprintf(cmd, sizeof cmd,
                  "while :; do t=$(grep TracerPid /proc/%d/status 2>/dev/null); "
                  "echo \"WD $t\" >&2; sleep %d; done",
                  static_cast<int>(getpid()),
                  static_cast<int>(kBeatPeriodMs / 1000));

    int fd = -1;
    if (spawn_fn(cmd, &fd) != 0 || fd < 0) return false;

    m.spawn = spawn_fn;
    std::memcpy(m.key, key, 16);
    m.fd = fd;
    m.pending.clear();
    m.tracer_pid = 0;
    return true;
}

void poll_monitor(Monitor& m, int64_t now_ms) {
    if (m.lv.started_ms == 0) liveness_init(m.lv, now_ms);
    if (m.fd < 0) return;

    // Drain everything currently available. poll(2) with timeout 0 BEFORE
    // every read(2) is load-bearing: an empty pipe with the write end still
    // open would block a bare read. EOF (child died) reads 0 and stops.
    char buf[512];
    for (;;) {
        struct pollfd pfd;
        pfd.fd = m.fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, 0) <= 0) break;
        ssize_t n = read(m.fd, buf, sizeof buf);
        if (n <= 0) break;
        m.pending.append(buf, static_cast<size_t>(n));
        if (static_cast<size_t>(n) < sizeof buf) break;
    }

    // Fold complete lines; a partial tail stays buffered for the next round.
    size_t beg = 0;
    for (;;) {
        size_t nl = m.pending.find('\n', beg);
        if (nl == std::string::npos) break;
        std::string line = m.pending.substr(beg, nl - beg);
        beg = nl + 1;
        bool ht = false;
        uint32_t tp = 0;
        if (parse_wd_line(line.c_str(), &ht, &tp)) {
            liveness_on_beat(m.lv, now_ms);
            // Absent/unparseable field never CLEARS a standing tracer report.
            if (ht) m.tracer_pid = tp;
        }
    }
    m.pending.erase(0, beg);
    if (m.pending.size() > kMaxPending) m.pending.clear();
}

Finding classify(const Monitor& m, int64_t now_ms) {
    if (m.fd < 0) return Finding::kNone;      // not running: fail-open
    if (m.tracer_pid != 0) return Finding::kTracer;
    if (missed_beats(m.lv, now_ms, kBeatPeriodMs) >= kSilentAfterMisses) {
        return Finding::kSilent;
    }
    return Finding::kNone;
}

void evidence(Monitor& m, Heartbeat& out) {
    beat(m.next_seq++, m.key, out);
}

}  // namespace dicore::watchdog
