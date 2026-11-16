#pragma once

#include <cstdint>

// H1 custody surface (parent side). The watchdog child holds 16 bytes of the
// NativeBridge.g unlock half (derived from the fork-inherited key, existing nowhere
// else) and releases 2 bytes per MAC-verified clean verdict. These accessors
// let the string gate query and consume the accumulated state; the state
// itself lives in watchdog.cpp beside the beat protocol that fills it.

namespace dicore {

// True when all 8 chunks (16 bytes) have been received and MAC-verified.
bool custody_complete();

// Re-verify all stored chunk MACs against the fork-inherited key. Returns
// false if any chunk was tampered (garbage written into g_custody_half
// without a matching MAC). The caller treats false as "custody not complete"
// — the derived key would be wrong anyway, producing silent garbage.
bool custody_verify();

// Copy the 16-byte child half into [out] (only meaningful when complete).
void custody_copy_half(uint8_t out[16]);

// H2.1 scorch: destroy the accumulated custody state so nothing re-assembles
// after enforcement escalation. Async-signal-safe.
void custody_scorch();

// State (defined in custody.cpp; written by the beat protocol in
// watchdog.cpp, read by the string gate).
extern uint8_t g_custody_half[16];
extern uint8_t g_custody_chunks;

// Store a verified chunk (called by the beat protocol in watchdog.cpp).
// Updates the half, the bitmask, and the integrity checksum atomically
// within the PROT_NONE page.
void custody_store_chunk(uint8_t chunk, uint8_t b0, uint8_t b1);

// Initialize the custody PROT_NONE page (call before fork, from do_init).
void custody_init();

}  // namespace dicore
