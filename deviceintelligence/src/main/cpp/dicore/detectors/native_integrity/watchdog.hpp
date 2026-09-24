// watchdog.hpp — INTEL_0060 fork-exec watchdog child (keyed heartbeat +
// liveness/tracer monitor).
//
// CONTRACT. The shim forks a plain /system/bin/sh child (only
// async-signal-safe calls between fork and exec; the Spawn indirection keeps
// that production spawn out of this host-testable TU). The child loops:
// re-read the PARENT's /proc/<pid>/status TracerPid and write
//     WD TracerPid:\t<value>
// to its stderr — dup2'd onto the private pipe's write end — every beat
// period. The parent-side engine here drains that pipe non-blocking
// (poll(2) BEFORE read(2), timeout 0, so an empty-but-open pipe never
// blocks), folds complete lines into a Liveness window, and classifies:
//
//   - cause=silent  — 3 consecutive missed beat periods (child killed,
//     silenced, or it never delivered a first beat; the grace anchor is the
//     monitor start time until the first beat lands);
//   - cause=tracer  — the child reported TracerPid != 0 (something is
//     ptrace-attached to the parent right now). A beat with an absent or
//     unparseable TracerPid field still counts as a BEAT (liveness) and
//     never clears a previously reported tracer — /proc or grep breakage
//     must degrade to liveness-only, not to a false all-clear.
//
// KEYED HEARTBEAT (evidence, INTEL_0058's anti-forgery shape): every emitted
// finding carries (seq, mac) where mac = SHA-256(key || be32(seq))
// truncated to 8 bytes. `check` is the verifier side (host tests today, the
// backend replay later): it recomputes the mac for the seq the caller
// EXPECTS and compares magic+seq+mac in one constant-time fold. Replay
// protection is consume-once by construction: the caller advances expect_seq
// on success, so a consumed Heartbeat re-presented at the new expect_seq
// fails the seq gate — same discipline as channel_guard's last_verified.
// v1 roots the key at a process-local random (crypto::secure_random in the
// probe); the token-crypto task rebinds it, see channel_guard_probe.cpp.
//
// Fail-open everywhere: spawn failure leaves the monitor inert (classify
// returns kNone, start is retried on later scans), garbage lines are not
// beats, and a newline-less flood cannot grow `pending` unboundedly.
// Detection-only — nothing here kills or respawns the child.
#pragma once

#include <cstdint>
#include <string>

namespace dicore::watchdog {

// fork+dup2(stderr)+execl("/system/bin/sh", "sh", "-c", cmd) — the production
// spawn lives in the probe TU; tests inject their own (real pipes).
using Spawn = int (*)(const char* cmd, int* pipe_out);

// ---- keyed heartbeat (pure) -------------------------------------------------

struct Heartbeat {
    uint32_t magic;
    uint32_t seq;
    uint8_t hmac[8];
};

// mac = SHA-256(key || be32(seq))[0..8). seq 0 is never a valid beat (it is
// the "nothing verified yet" marker on the verifier side).
void beat(uint32_t seq, const uint8_t key[16], Heartbeat& out);

// True iff hb is a fresh heartbeat for exactly expect_seq under key:
// constant-time fold over magic, seq and all 8 mac bytes; expect_seq 0 always
// fails. Consume-once is the caller's advancing of expect_seq (see header
// contract).
bool check(const Heartbeat& hb, uint32_t expect_seq, const uint8_t key[16]);

// ---- liveness windows (pure, time injected) ---------------------------------

constexpr int64_t kBeatPeriodMs = 2000;   // must match the child cmd's sleep
constexpr int kSilentAfterMisses = 3;     // consecutive missed beats -> finding

struct Liveness {
    int64_t started_ms;    // monitor start (grace anchor until first beat)
    int64_t last_beat_ms;  // 0 = no beat accepted yet
};

void liveness_init(Liveness& lv, int64_t now_ms);
void liveness_on_beat(Liveness& lv, int64_t now_ms);

// Full beat periods elapsed with no beat since the last one (or since start,
// before the first). Beat due every period, so this IS the count of
// consecutive missed beats at now_ms.
int missed_beats(const Liveness& lv, int64_t now_ms, int64_t period_ms);

// ---- WD-line parsing (pure) -------------------------------------------------

// A beat line is "WD" optionally followed by whitespace and a payload; when
// the payload is "TracerPid:<ws><digits>" the tracer value is reported.
// Returns whether the line is a beat at all; *has_tracer says whether a
// tracer value was parsed (*tracer_pid only written when true).
bool parse_wd_line(const char* line, bool* has_tracer, uint32_t* tracer_pid);

// ---- monitor engine (host-testable: I/O is plain pipe fd, time injected) ----

enum class Finding { kNone, kSilent, kTracer };

struct Monitor {
    Spawn spawn = nullptr;
    uint8_t key[16] = {};
    int fd = -1;                 // read end of the child pipe; <0 = not running
    Liveness lv{};
    uint32_t tracer_pid = 0;     // latest parsed TracerPid report (0 = clean)
    std::string pending;         // partial line bytes across drains
    uint32_t next_seq = 1;       // evidence heartbeat sequence
};

// Idempotent. Builds the child cmd (parent pid substituted into the
// /proc/<pid>/status read), launches via spawn_fn. False (monitor left
// inert) if spawn_fn fails — retry on a later call is the caller's choice.
bool start(Monitor& m, const uint8_t key[16], Spawn spawn_fn);

// One non-blocking monitoring round at now_ms: lazily anchors liveness on
// first call, drains everything currently readable, folds complete WD lines
// (stamping this round's now_ms — a long-idle pipe therefore reports its
// drained beats as fresh, costing at most one classification period of
// detection latency, never a false silent).
void poll_monitor(Monitor& m, int64_t now_ms);

// Tracer wins over silent (the stronger, ongoing evidence stands). Not
// started (spawn failed / never called) is fail-open kNone, never a finding.
Finding classify(const Monitor& m, int64_t now_ms);

// Fresh evidence heartbeat for a record about to be emitted; advances seq.
void evidence(Monitor& m, Heartbeat& out);

} // namespace dicore::watchdog
