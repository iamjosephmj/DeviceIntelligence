// deviceintelligence/src/main/cpp/test/detectors/native_integrity/test_watchdog.cpp
// Host test for the INTEL_0018 watchdog: the pure keyed-heartbeat core
// (beat/check), the WD-line parser, the liveness window arithmetic, and the
// monitor engine driven through an injected Spawn that writes synthetic
// beats through a REAL pipe (no mocks of the pipe/fd machinery).
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include "dicore/detectors/native_integrity/watchdog.hpp"

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

using namespace dicore::watchdog;

// ---- injected spawns (deterministic; real pipes) --------------------------

static std::string g_last_cmd;
static uint32_t g_fake_tracer = 0;
static bool g_fake_child_dies = false;

static int spawn_fail(const char*, int*) { return -1; }

// Writes one synthetic beat line into a real pipe. Write end stays open
// (= live child) unless g_fake_child_dies, in which case it closes after
// the line (child killed right after its last beat).
static int spawn_beats(const char* cmd, int* pipe_out) {
    g_last_cmd = cmd;
    int fds[2];
    if (pipe(fds) != 0) return -1;
    char line[64];
    int n = snprintf(line, sizeof line, "WD TracerPid:\t%u\n", g_fake_tracer);
    if (write(fds[1], line, (size_t)n) != n) { close(fds[0]); close(fds[1]); return -1; }
    if (g_fake_child_dies) close(fds[1]);
    *pipe_out = fds[0];
    return 0;
}

int main() {
    uint8_t key[16]; for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 1);
    uint8_t key2[16]; memcpy(key2, key, 16); key2[0] ^= 0xA5;

    // ---- keyed heartbeat: beat/check --------------------------------------
    Heartbeat hb; beat(1, key, hb);
    CHECK(hb.magic != 0);
    CHECK(check(hb, 1, key));                       // roundtrip
    CHECK(!check(hb, 1, key2));                     // wrong key
    CHECK(!check(hb, 2, key));                      // seq skip (expect ahead)
    CHECK(!check(hb, 0, key));                      // seq 0 never verifies
    Heartbeat hb0; beat(0, key, hb0);
    CHECK(!check(hb0, 0, key));                     // a beat OF seq 0 is not fresh
    CHECK(!check(hb, 5, key));                      // expect far ahead
    // replay: consumed at expect 1, the same struct replayed at expect 2 fails
    uint32_t expect = 1;
    CHECK(check(hb, expect, key));
    expect++;                                       // consume-once: caller advances
    CHECK(!check(hb, expect, key));
    // magic tamper
    Heartbeat tm = hb; tm.magic ^= 1;
    CHECK(!check(tm, 1, key));
    // every hmac byte matters (constant-time fold sees all 8 bytes)
    for (int i = 0; i < 8; i++) {
        Heartbeat th = hb; th.hmac[i] ^= 0x01;
        CHECK(!check(th, 1, key));
    }
    // determinism + seq sensitivity
    Heartbeat a, b, c;
    beat(7, key, a); beat(7, key, b); beat(8, key, c);
    CHECK(memcmp(a.hmac, b.hmac, 8) == 0);
    CHECK(memcmp(a.hmac, c.hmac, 8) != 0);

    // ---- WD-line parser ----------------------------------------------------
    bool ht = false; uint32_t tp = 999;
    CHECK(parse_wd_line("WD TracerPid:\t0", &ht, &tp) && ht && tp == 0);
    CHECK(parse_wd_line("WD TracerPid:\t54321", &ht, &tp) && ht && tp == 54321);
    ht = true; tp = 42;
    CHECK(parse_wd_line("WD ", &ht, &tp) && !ht && tp == 42);   // bare beat: field untouched
    CHECK(parse_wd_line("WD", &ht, &tp) && !ht);
    CHECK(parse_wd_line("WD other-noise", &ht, &tp) && !ht);    // beat, no tracer info
    ht = true;
    CHECK(parse_wd_line("WD TracerPid:", &ht, &tp) && !ht);     // prefix, no digits
    CHECK(!parse_wd_line("TracerPid:\t9", &ht, &tp));           // not a WD line
    CHECK(!parse_wd_line("hello WD", &ht, &tp));
    CHECK(!parse_wd_line("", &ht, &tp));
    CHECK(!parse_wd_line(nullptr, &ht, &tp));

    // ---- liveness window arithmetic ---------------------------------------
    Liveness lv; liveness_init(lv, 1000);
    CHECK(missed_beats(lv, 1000, 2000) == 0);
    CHECK(missed_beats(lv, 2999, 2000) == 0);
    CHECK(missed_beats(lv, 5999, 2000) == 2);       // grace counts from start
    CHECK(missed_beats(lv, 7000, 2000) == 3);       // dead child -> silent at 3 periods
    liveness_on_beat(lv, 6500);
    CHECK(missed_beats(lv, 7000, 2000) == 0);       // beat resets
    CHECK(missed_beats(lv, 8500, 2000) == 1);
    CHECK(missed_beats(lv, 6000, 2000) == 0);       // now before anchor

    // ---- monitor: spawn failure is fail-open -------------------------------
    Monitor m4;
    CHECK(!start(m4, key, spawn_fail));
    CHECK(classify(m4, 1000000) == Finding::kNone);
    poll_monitor(m4, 1000000);                      // must be a safe no-op
    CHECK(classify(m4, 1000000) == Finding::kNone);

    // ---- monitor: live clean child -> no finding ---------------------------
    g_fake_tracer = 0; g_fake_child_dies = false;
    Monitor m;
    CHECK(start(m, key, spawn_beats));
    CHECK(m.fd >= 0);
    CHECK(strstr(g_last_cmd.c_str(), "TracerPid") != nullptr);
    CHECK(strstr(g_last_cmd.c_str(), "/proc/") != nullptr);
    CHECK(strstr(g_last_cmd.c_str(), "sleep 2") != nullptr);
    poll_monitor(m, 100000);
    CHECK(m.lv.last_beat_ms == 100000);
    CHECK(m.tracer_pid == 0);
    CHECK(classify(m, 100000) == Finding::kNone);
    CHECK(classify(m, 100000 + 2 * kBeatPeriodMs) == Finding::kNone);
    CHECK(classify(m, 100000 + 3 * kBeatPeriodMs) == Finding::kSilent);  // went quiet

    // ---- monitor: child reports a tracer ----------------------------------
    g_fake_tracer = 31337;
    Monitor m2;
    CHECK(start(m2, key, spawn_beats));
    poll_monitor(m2, 200000);
    CHECK(m2.tracer_pid == 31337);
    CHECK(classify(m2, 200000) == Finding::kTracer);
    CHECK(classify(m2, 200000 + 9 * kBeatPeriodMs) == Finding::kTracer); // beats silent, tracer stands

    // ---- monitor: killed child -> 3 missed beats -> silent -----------------
    g_fake_tracer = 0; g_fake_child_dies = true;
    Monitor m3;
    CHECK(start(m3, key, spawn_beats));
    poll_monitor(m3, 300000);
    CHECK(classify(m3, 300000) == Finding::kNone);
    CHECK(classify(m3, 300000 + 3 * kBeatPeriodMs - 1) == Finding::kNone);
    CHECK(classify(m3, 300000 + 3 * kBeatPeriodMs) == Finding::kSilent);

    // ---- monitor: partial lines buffered across polls ----------------------
    int fds[2];
    CHECK(pipe(fds) == 0);
    Monitor m5;
    m5.fd = fds[0];
    CHECK(write(fds[1], "WD TracerPid:\t", 14) == 14);
    poll_monitor(m5, 10);
    CHECK(m5.lv.last_beat_ms == 0);                 // incomplete line: no beat yet
    CHECK(write(fds[1], "5\n", 2) == 2);
    poll_monitor(m5, 20);
    CHECK(m5.lv.last_beat_ms == 20);
    CHECK(m5.tracer_pid == 5);
    // multiple beats in one drain: the LAST tracer field wins
    CHECK(write(fds[1], "WD TracerPid:\t3\nWD TracerPid:\t4\n", 32) == 32);
    poll_monitor(m5, 30);
    CHECK(m5.tracer_pid == 4);
    close(fds[1]); close(fds[0]);

    // ---- monitor: newline-less flood cannot grow pending unbounded --------
    int fds2[2];
    CHECK(pipe(fds2) == 0);
    Monitor m6;
    m6.fd = fds2[0];
    std::string flood(20000, 'x');
    CHECK(write(fds2[1], flood.data(), flood.size()) == (ssize_t)flood.size());
    poll_monitor(m6, 40);
    CHECK(m6.pending.size() <= 8192);
    CHECK(m6.lv.last_beat_ms == 0);                 // garbage is never a beat
    close(fds2[1]); close(fds2[0]);

    // ---- evidence pairs: fresh seq each emit, verifiable, replay-fail -----
    Monitor m7;
    CHECK(start(m7, key, spawn_beats));
    poll_monitor(m7, 400000);
    Heartbeat e1, e2;
    evidence(m7, e1);
    evidence(m7, e2);
    CHECK(e1.seq == 1 && e2.seq == 2);
    CHECK(check(e1, 1, key));
    CHECK(!check(e1, 2, key));

    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
