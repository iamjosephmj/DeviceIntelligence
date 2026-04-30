#pragma once

// G4 — GOT integrity verification.
//
// libdicore has its own Global Offset Table — `.got` (used for
// data references such as PIC globals) and `.got.plt` (used for
// lazy-bound function calls). At process load the dynamic linker
// fills each slot with the resolved address of an imported
// symbol; once filled, those slots are read at the top of every
// PLT trampoline. Overwriting a single GOT slot replaces the
// resolved import, which is the canonical Frida / xHook /
// PLTHook attack on a native library.
//
// Per-scan we re-read each slot, classify it via `range_map`,
// and emit:
//   - `got_entry_drifted`     (HIGH)     — slot value changed
//      since the JNI_OnLoad snapshot
//   - `got_entry_out_of_range` (CRITICAL) — slot value resolves
//      to memory outside any system library (frida trampoline,
//      attacker-allocated page, etc).
//
// The snapshot is held in PROT_NONE pages with a hash-of-the-
// snapshot audit (same defense as `text_verify` G2).

#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {

/**
 * G4 — captures the GOT/`got.plt` snapshot from libdicore. Safe
 * to call from JNI_OnLoad after `range_map::initialize_ranges`
 * has captured libdicore's load address. Idempotent. No-ops if
 * the on-disk libdicore.so can't be opened or section headers
 * can't be parsed.
 */
void initialize_got_verify();

/** One per-slot scan record. */
struct GotRecord {
    uint32_t slot_index;
    uint8_t  live_class;       // dicore::native_integrity::Region as uint8_t
    uint8_t  snapshot_class;
    bool     drifted;
    bool     out_of_range;
    uintptr_t live_value;
    uintptr_t snapshot_value;
};

/**
 * Re-reads every snapshotted slot, fills [out] with up to
 * [capacity] records, returns the number of FLAGGED records
 * (those with `drifted` || `out_of_range`). A clean device
 * returns 0; the caller does not need to filter.
 *
 * Returns SIZE_MAX if the snapshot was never captured (G4
 * unavailable on this device).
 */
size_t scan_got_integrity(GotRecord* out, size_t capacity);

}  // namespace dicore::native_integrity
