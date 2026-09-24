#pragma once

// A2 — anti-reentrant JNI_OnLoad gate.
//
// The attack campaign's re-trigger technique re-invokes JNI_OnLoad inside an
// already-loaded libdicore (e.g. via a stolen dlopen handle or a direct
// call through the export) to re-run the snapshot/baseline captures against
// attacker-controlled memory. Re-running capture against a hooked process
// launders the hooks into the baselines, so a second entry must never
// complete: the first OnLoad arms the gate, any later entry finds it armed
// and the caller abort()s — re-invocation is now a kill, not a re-trigger.
//
// Pure atomic logic (single CAS), host-testable without a JVM:
// test/jni/test_reentry_guard.cpp pins first-win, second-lose and the
// two-thread exactly-one-winner contract.

#include <atomic>
#include <cstdint>

namespace dicore::reentry {

// Atomically transitions `gate` 0 -> 1. Returns true exactly once per gate
// (the first caller); every later caller gets false.
inline bool arm(std::atomic<uint32_t>& gate) {
    uint32_t expected = 0u;
    return gate.compare_exchange_strong(
            expected, 1u, std::memory_order_acq_rel, std::memory_order_acquire);
}

} // namespace dicore::reentry
