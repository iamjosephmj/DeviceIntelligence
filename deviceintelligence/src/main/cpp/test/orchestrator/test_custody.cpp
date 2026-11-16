// Host unit tests for the anti-clone custody gate:
//   1. custody page semantics (store -> complete -> verify -> scorch)
//   2. the full forked-child protocol: 8 chunks released on clean beats
//   3. the gated string wait (publish + custody complete -> U)
// Compiled with -DDICORE_WD_TEST=1 (shrinks the beat period); that flag is
// never set in release builds.
#include "dicore/enforce/custody.h"
#include "dicore/orchestrator/custody_wd.h"
#include "dicore/platform/string_gate.h"
#include "dicore/crypto/sha256.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>

using namespace dicore;

static bool wait_complete(int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (custody_complete()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return custody_complete();
}

int main() {
    // ---- 1. custody page semantics (pure, no child) ----
    custody_init();   // allocate the PROT_NONE page (no-op if already up)
    assert(!custody_complete());
    assert(!custody_verify());
    for (uint8_t i = 0; i < 8; ++i) {
        custody_store_chunk(i, static_cast<uint8_t>(0x30 + i), static_cast<uint8_t>(0x70 + i));
    }
    assert(custody_complete());
    uint8_t half[16];
    custody_copy_half(half);
    for (uint8_t i = 0; i < 8; ++i) {
        assert(half[i * 2] == static_cast<uint8_t>(0x30 + i));
        assert(half[i * 2 + 1] == static_cast<uint8_t>(0x70 + i));
    }
    assert(custody_verify());
    // Duplicate chunk delivery (respawned child re-releases) is idempotent.
    custody_store_chunk(3, 0x33, 0x73);
    assert(custody_complete() && custody_verify());
    // Scorch tears the state down: incomplete again.
    custody_scorch();
    assert(!custody_complete());
    assert(!custody_verify());

    // ---- 2. full forked-child protocol (fast beats, test-only flag) ----
    custody_wd_set_beat_period_ms_for_test(20);
    custody_wd_init();
    custody_wd_note_clean_sweep();
    // The child releases 1 chunk per beat; 8 chunks at 20ms beats land in well
    // under a second, but allow a generous 30s for loaded CI hosts.
    assert(wait_complete(30000));
    assert(custody_verify());

    // ---- 3. gated string wait ----
    string_gate_publish();
    uint8_t u[32];
    string_gate_wait(u);
    uint8_t expect[32];
    const char* phrase = "dicore-unlock-mix-v1";
    assert(sha::sha256(phrase, strlen(phrase), expect));
    assert(memcmp(u, expect, 32) == 0);

    std::printf("test_custody: page semantics + forked-child release + gated wait OK\n");
    return 0;
}
