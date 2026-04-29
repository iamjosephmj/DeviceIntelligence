#pragma once

// F18 — Vector F: ArtMethod->access_flags_ ACC_NATIVE bit watch.
//
// The single most reliable signal Frida-Java's
// `cls.method.implementation = ...` leaves behind: when it hooks
// a non-native Java method, it flips `ACC_NATIVE` ON so ART's
// dispatcher routes the call through the JNI-bridge slot (where
// Frida-Java has installed its trampoline). The flip is binary
// and unambiguous — Java methods never become native at runtime
// under normal operation, so a 0→1 transition on `ACC_NATIVE` is
// proof-positive of a Frida-Java (or comparable) hook.
//
// Storage: same self-protected pattern as Vectors A / C / E —
// snapshot bits live in a PROT_NONE mmap'd page with a
// separately-allocated SHA-256 hash page. The values themselves
// are tiny (one `uint32_t` per registry slot), but the storage
// shape mirrors the other vectors so an attacker who has learned
// to scan-and-edit one storage page learns nothing extra about
// where the others live.
//
// Per-method semantics:
//
//   - **Native methods**: `ACC_NATIVE` is already set; flipping
//     it OFF would itself be a tamper signal. We watch for both
//     directions but log/finding-emit on flip-on (the Frida-Java
//     case) at higher severity.
//
//   - **Non-native methods**: `ACC_NATIVE` is unset at JNI_OnLoad.
//     Flip-on => Frida-Java hook installed.
//
// The full `access_flags_` value is also captured (not just the
// native bit) so that future vectors can extend this same
// snapshot to watch other modifier bits (`ACC_FAST_NATIVE`,
// `ACC_SKIP_ACCESS_CHECKS`) without re-mmapping.

#include <cstddef>
#include <cstdint>

namespace dicore::art_integrity {

struct AccessFlagsScanEntry {
    const char* short_id;
    uint32_t snapshot_flags;
    uint32_t live_flags;
    bool readable;             // false => INDEX-encoded jmethodID; skip
    bool native_flipped_on;    // ACC_NATIVE 0 -> 1
    bool native_flipped_off;   // ACC_NATIVE 1 -> 0 (rare, also tamper)
    bool any_drift;            // snapshot_flags != live_flags
};

constexpr size_t kAccessFlagsMaxEntries = 32;

/**
 * Snapshots `access_flags_` for every registry slot. Idempotent.
 * Must be called from `JNI_OnLoad` after `registry::initialize`.
 */
void initialize_access_flags();

/**
 * Re-reads `access_flags_` for each registry slot, computes the
 * diff vs the snapshot, writes one entry per slot into [out].
 * Returns the number written.
 */
size_t scan_access_flags(AccessFlagsScanEntry* out, size_t out_capacity);

/**
 * True when the protected snapshot's hash matched its values on
 * the most recent scan.
 */
bool last_access_flags_baseline_intact();

}  // namespace dicore::art_integrity
