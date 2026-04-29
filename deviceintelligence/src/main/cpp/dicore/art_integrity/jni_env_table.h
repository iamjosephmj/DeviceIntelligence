#pragma once

// F18 — Vector C: JNIEnv function-table snapshot + diff.
//
// Frida-Java's hook machinery routinely rewrites pointers inside
// `JNINativeInterface` (the function table that JNIEnv->functions
// points to) — `GetMethodID`, `RegisterNatives`, `CallStaticIntMethod`
// and friends. The table is shared process-wide on ART
// (it's `gJniInvokeInterface`), so a single rewrite affects every
// JNI caller in the app.
//
// Vector C snapshots the pointers we care about at JNI_OnLoad
// (no lazy-resolution problem here — these pointers don't legitimately
// transition during normal execution), stores them in a separately-
// allocated PROT_NONE mmap page (mirroring the Vector A storage
// pattern), and re-reads them on each evaluate. Each scan emits:
//
//   - `jni_env_table_out_of_range` (HIGH) — live pointer falls
//     outside libart's RX segment.
//   - `jni_env_table_drifted` (HIGH) — live pointer differs from
//     snapshot. No JIT-cache exception here; JNI table pointers
//     don't legitimately move.

#include "ranges.h"

#include <jni.h>

#include <cstddef>

namespace dicore::art_integrity {

struct JniEnvScanEntry {
    const char* function_name;   // e.g. "GetMethodID"
    const void* snapshot_fn;
    const void* live_fn;
    Classification snapshot_class;
    Classification live_class;
    bool drifted;
};

constexpr size_t kJniEnvWatched = 8;

/**
 * Snapshots the watched JNIEnv function pointers into a self-
 * protected mmap page. Idempotent. Called from `JNI_OnLoad` so
 * the snapshot precedes any post-load attacker.
 */
void initialize_jni_env(JNIEnv* env);

/**
 * Re-reads the watched pointers, classifies each, computes diff
 * vs the protected snapshot, writes one entry per watched
 * function into [out]. Returns the number written (always
 * `kJniEnvWatched` once initialised).
 */
size_t scan_jni_env(JNIEnv* env, JniEnvScanEntry* out, size_t out_capacity);

/**
 * Returns true if the protected snapshot's hash matched its
 * values on the most recent scan. False means the page was
 * tampered with between scans (Vector C's `jni_env_table_baseline_tampered`).
 */
bool last_jni_env_baseline_intact();

}  // namespace dicore::art_integrity
