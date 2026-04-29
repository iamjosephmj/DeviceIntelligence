#pragma once

// F18 — Vector E: ArtMethod->entry_point_from_jni_ snapshot + diff.
//
// Closes the blind spot in Vector A: Frida-Java's
// `cls.method.implementation = ...` does NOT touch
// `entry_point_from_quick_compiled_code_` (Vector A's field).
// Instead it writes its bridge pointer into `entry_point_from_jni_`
// (the `data_` slot) and — for non-native methods — flips the
// `ACC_NATIVE` bit (Vector F handles that bit flip).
//
// This module mirrors Vector A's storage pattern (PROT_NONE
// mmap'd snapshot + separately-allocated SHA-256 hash page) but
// reads a different ArtMethod field.
//
// Per-method semantics:
//
//   - **Native methods** (kind == JNI_NATIVE): `entry_point_from_jni_`
//     is the JNI dispatch stub inside libart; it does not move
//     during normal execution. Drift here is unambiguous tamper.
//
//   - **Non-native methods**: the same slot is `data_` and ART
//     uses it for ProfilingInfo / hotness counters. Its value
//     legitimately changes due to JIT activity. We therefore
//     restrict the diff to slots that started out classified
//     inside libart (the JNI bridge case) — ProfilingInfo
//     pointers land in art-managed heaps, not libart's RX, so
//     the snapshot classification disambiguates the two without
//     needing to bake a `is_native` per-slot flag here.

#include "ranges.h"

#include <cstddef>
#include <cstdint>

namespace dicore::art_integrity {

struct JniEntryScanEntry {
    const char* short_id;
    const void* snapshot_entry;  // entry_point_from_jni_ at JNI_OnLoad
    const void* live_entry;      // re-read at scan time
    Classification snapshot_class;
    Classification live_class;
    bool readable;               // false => INDEX-encoded jmethodID; skip
    bool drifted;                // snapshot_entry != live_entry
    bool is_native_by_spec;      // method declared `native` in JDK (registry kind == JNI_NATIVE).
                                 // Distinct from the runtime ACC_NATIVE bit because ART
                                 // intrinsifies some declared-native methods (Object#hashCode
                                 // etc) and clears the ACC_NATIVE bit on them, even though
                                 // their `data_` slot still holds the JNI bridge pointer.
};

constexpr size_t kJniEntryMaxEntries = 32;

/**
 * Snapshots `entry_point_from_jni_` for every registry slot into
 * a self-protected mmap page. Idempotent. Must be called from
 * `JNI_OnLoad` (after `registry::initialize`) so the snapshot
 * precedes any post-load Frida-Java attach.
 */
void initialize_jni_entry();

/**
 * Re-reads `entry_point_from_jni_` for each registry slot,
 * classifies each, computes diff vs the protected snapshot,
 * writes one entry per registry slot into [out]. Returns the
 * number written.
 */
size_t scan_jni_entry(JniEntryScanEntry* out, size_t out_capacity);

/**
 * True when the protected snapshot's hash matched its values on
 * the most recent scan. False means the page itself was tampered
 * with between scans.
 */
bool last_jni_entry_baseline_intact();

}  // namespace dicore::art_integrity
