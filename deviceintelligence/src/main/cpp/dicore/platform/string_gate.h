#pragma once

#include <cstdint>

// Sweep-gated string-key unlock. The clean-sweep path publishes
// the 32-byte unlock secret U; the gated key entry (NativeBridge.g) blocks until then.
namespace dicore {

// Compute U = SHA256("dicore-unlock-mix-v1"), store it, and wake all waiters.
// Idempotent. MUST be called only on dicore_orchestrate's critical==0 path.
void string_gate_publish();

// Block (no timeout) until publish() has run AND the custody protocol has
// delivered all 8 MAC-verified chunks from the forked watchdog child, then
// copy the 32-byte U into out. An in-process caller that skips the sweep can
// call publish() itself — that yields only the parent half; the child half
// cannot be assembled without a genuinely forked child of a clean sweep.
void string_gate_wait(uint8_t out[32]);

}  // namespace dicore
