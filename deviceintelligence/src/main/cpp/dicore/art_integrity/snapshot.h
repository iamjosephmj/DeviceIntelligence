#pragma once

// F18 — Vector A snapshot store + live-scan engine.
//
// Two-step contract that powers both Vector A's range check (M4)
// and its diff check (M5):
//
//   1. M2 captures the entry pointer at JNI_OnLoad as part of
//      `registry::initialize` and exposes it as
//      `ResolvedMethod::entry_point`. That value is informational
//      (used by M3's classification logging) but is NOT used as
//      the diff baseline.
//
//   2. The diff baseline is captured on the FIRST scan — i.e. the
//      first time `scan_live` runs after the app has done some
//      work. This skips a large class of legitimate transitions
//      that happen between `JNI_OnLoad` and the first observable
//      evaluate (the ART JNI dispatch stub `art_jni_dlsym_lookup_stub`
//      transitions to the resolved JNI binding the first time
//      each native method is called, which would false-positive
//      every JNI-native frozen method on a fresh app start).
//
//   3. Every subsequent scan compares live entries to the stable
//      baseline and reports drift when they differ.
//
// Trade-off: an attacker injected between JNI_OnLoad and the
// first evaluate poisons the baseline and Vector A's diff check
// misses them. Vector D's prologue-baseline check is the
// compensating control for that case (its baseline is embedded
// at SDK build time, immune to runtime injection).
//
// M6 will move the baseline off-heap and harden the integrity
// check (PROT_NONE mmap + separately-stored hash). For M4 + M5
// the baseline lives in plain process memory — M6 swaps it for
// the protected variant without changing this header.

#include "ranges.h"

#include <cstddef>
#include <cstdint>

namespace dicore::art_integrity {

/**
 * Per-method live state. One entry per registry slot. Always
 * `registry_size()` entries; entries that aren't readable
 * (INDEX-encoded jmethodIDs, classes that didn't resolve) carry
 * `readable=false` and otherwise zero values so callers can
 * iterate uniformly.
 */
struct ScanEntry {
    const char* short_id;        // stable forensic identifier
    const void* snapshot_entry;  // captured at JNI_OnLoad
    const void* live_entry;      // re-read at scan time
    Classification snapshot_class;
    Classification live_class;
    bool readable;               // false => skip for findings
    bool drifted;                // snapshot_entry != live_entry
};

/**
 * Maximum number of scan entries returned. Sized to comfortably
 * fit the current frozen-method registry; raising the registry's
 * size requires bumping this constant too. Compile-time so the
 * caller can stack-allocate.
 */
constexpr size_t kMaxScanEntries = 32;

/**
 * Walks every registry slot, reads the live entry pointer,
 * classifies it, computes the snapshot/live diff, and writes
 * the result into [out] (up to [out_capacity] entries). Returns
 * the number of entries written.
 *
 * Idempotent and side-effect-free aside from re-reading
 * `ArtMethod` fields. Safe to call from any thread.
 */
size_t scan_live(ScanEntry* out, size_t out_capacity);

/**
 * Returns true if, on the most recent [scan_live] call, the
 * baseline page's stored SHA-256 hash matched the recomputed
 * hash of the values. False means an attacker scanned and
 * tampered with our baseline storage between scans — that's a
 * Vector A finding all on its own (`art_baseline_tampered`).
 *
 * Always true on the very first scan (no prior baseline to
 * verify) and across any scan where the baseline was just
 * captured.
 */
bool last_scan_baseline_intact();

}  // namespace dicore::art_integrity
