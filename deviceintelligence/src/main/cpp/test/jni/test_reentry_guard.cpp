// deviceintelligence/src/main/cpp/test/jni/test_reentry_guard.cpp
// Host test for the JNI_OnLoad anti-reentry gate (so-hardening A2). arm() is
// pure atomic logic — one CAS 0→1 decides first-win — so the whole contract
// is host-testable without a JVM: first call arms (true), every later call on
// the same gate loses (false), and under a barrier-started multi-thread race
// exactly one arm wins per gate, every iteration. On device the loser is
// JNI_OnLoad's second entry, which abort()s.
#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>
#include "dicore/jni/reentry_guard.h"

#include <cstdio>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main() {
    using dicore::reentry::arm;

    // --- first call on a fresh gate wins and flips 0 -> 1 ---
    std::atomic<uint32_t> g1{0};
    CHECK(arm(g1) == true);
    CHECK(g1.load() == 1u);

    // --- every subsequent call on the same gate loses ---
    CHECK(arm(g1) == false);
    CHECK(arm(g1) == false);
    CHECK(g1.load() == 1u);  // gate stays armed, never re-arms

    // --- independent gates don't interfere ---
    std::atomic<uint32_t> g2{0};
    CHECK(arm(g2) == true);
    CHECK(arm(g1) == false);  // g1 still consumed

    // --- barriered race loop: ~1000 fresh gates, exactly one winner each ---
    // A naive spawn-then-arm race cannot discriminate a broken arm(): the OS
    // serializes thread startup, so even check-then-set threads arrive one at
    // a time and still produce a single winner. Every iteration parks all
    // racers on a ready/go barrier so their first load of the fresh gate
    // lands in the same window — a check-then-set arm() lets several through
    // at once and the per-iteration assertion catches it. Widths alternate
    // 2/8 threads (500 gates each); yield-spins keep it single-core-safe.
    {
        constexpr int kIters = 1000;
        for (int iter = 0; iter < kIters; ++iter) {
            const int n = (iter % 2 == 0) ? 2 : 8;
            std::atomic<uint32_t> gate{0};
            std::atomic<uint32_t> wins{0};
            std::atomic<uint32_t> ready{0};
            std::atomic<bool> go{false};
            std::vector<std::thread> ts;
            ts.reserve(n);
            for (int i = 0; i < n; ++i) {
                ts.emplace_back([&] {
                    ready.fetch_add(1, std::memory_order_acq_rel);
                    while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
                    if (arm(gate)) wins.fetch_add(1, std::memory_order_relaxed);
                });
            }
            while (ready.load(std::memory_order_acquire) != static_cast<uint32_t>(n)) {
                std::this_thread::yield();
            }
            go.store(true, std::memory_order_release);
            for (auto& t : ts) t.join();
            if (wins.load() != 1u || gate.load() != 1u) {
                printf("FAIL iter=%d n=%d wins=%u gate=%u (want 1/1)\n",
                       iter, n, wins.load(), gate.load());
                CHECK(false);  // first-win, no double-arm — violated
                break;         // report first bad iteration, skip the rest
            }
        }
    }

    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
