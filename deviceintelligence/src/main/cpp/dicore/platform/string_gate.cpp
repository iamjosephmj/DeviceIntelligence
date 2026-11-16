#include "dicore/platform/string_gate.h"

#include "dicore/enforce/custody.h"
#include "dicore/crypto/sha256.h"      // sha::sha256 / sha::ensure_initialized / sha::kDigestLen
#include "dicore/platform/obf.h"       // DI_OBF_MAX

#include <pthread.h>
#include <unistd.h>
#include <cstring>

namespace dicore {
namespace {
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  g_cond  = PTHREAD_COND_INITIALIZER;
bool            g_published = false;
uint8_t         g_unlock[32] = {0};
}  // namespace

DI_OBF_MAX __attribute__((noinline))
void string_gate_publish() {
    if (!sha::ensure_initialized()) return;          // no crypto -> stays gated
    uint8_t u[sha::kDigestLen];
    const char* phrase = "dicore-unlock-mix-v1";
    if (!sha::sha256(phrase, std::strlen(phrase), u)) return;
    pthread_mutex_lock(&g_mutex);
    if (!g_published) {
        std::memcpy(g_unlock, u, 32);
        g_published = true;
        pthread_cond_broadcast(&g_cond);
    }
    pthread_mutex_unlock(&g_mutex);
}

DI_OBF_MAX __attribute__((noinline))
void string_gate_wait(uint8_t out[32]) {
    pthread_mutex_lock(&g_mutex);
    while (!g_published) pthread_cond_wait(&g_cond, &g_mutex);
    pthread_mutex_unlock(&g_mutex);
    // H1 anti-clone custody: the unlock material is only consumable once the
    // forked watchdog child has released all 8 custody chunks across MAC-
    // verified clean verdicts. Calling string_gate_publish() directly yields
    // only the parent half of the gate — this loop then blocks forever on the
    // missing child half. custody_verify() additionally re-checks the page
    // integrity checksum: garbage written into the custody page without the
    // checksum never completes the wait (the derived key would be wrong
    // anyway — this just makes it explicit).
    while (!custody_complete() || !custody_verify()) {
        usleep(50000);   // 50ms poll; the child releases ~1 chunk per beat (2s)
    }
    // Return the PUBLISHED material unmixed. The custody protocol gates this
    // function's AVAILABILITY (the wait cannot complete without the child's 8
    // MAC-verified chunks following a clean sweep) — it must NOT feed the key
    // VALUE: the build-time baker encrypts with U = SHA256(unlock phrase), and
    // custody_half is per-process random, so mixing it in here would break
    // baker<->runtime lockstep and decrypt every baked string to garbage.
    // Timing is the defense; the bytes are the contract.
    pthread_mutex_lock(&g_mutex);
    std::memcpy(out, g_unlock, 32);
    pthread_mutex_unlock(&g_mutex);
}

}  // namespace dicore
