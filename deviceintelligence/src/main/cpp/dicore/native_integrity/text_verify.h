#pragma once

// G2 — `.text` self-integrity. Snapshots the SHA-256 of
// libdicore.so's executable PT_LOAD segment at JNI_OnLoad and
// re-checks it on every scan against:
//   - the build-time hash baked into the fingerprint blob
//     (`Fingerprint.dicoreTextSha256ByAbi`), supplied by the
//     runtime via `set_expected_text_hash()`. Mismatch =>
//     `native_text_hash_mismatch` (the on-disk .so was replaced
//     before load).
//   - the runtime snapshot captured at JNI_OnLoad. Mismatch =>
//     `native_text_drifted` (someone mprotect+memcpy'd .text
//     after load).
//
// Both baselines live in mmap'd PROT_NONE pages (same pattern
// as art_integrity/snapshot.cpp); we PROT_READ them only for
// the duration of a scan and then PROT_NONE them again.

#include <cstddef>
#include <cstdint>
#include <jni.h>

namespace dicore::native_integrity {

/**
 * Captures the SHA-256 of libdicore's RX segment as the
 * runtime snapshot. Safe to call from JNI_OnLoad. Idempotent;
 * subsequent calls are no-ops. Requires `range_map::initialize_ranges`
 * to have run first.
 */
void initialize_text_verify();

/**
 * Stores the build-time expected `.text` hash (lowercase hex of
 * 32 bytes). Called once per process from Kotlin via
 * `NativeBridge.initNativeIntegrity` after the fingerprint blob
 * has been decoded. Empty string disables the build-time check
 * (used when the v1 fingerprint is decoded — no hash available).
 */
void set_expected_text_hash(const char* hex32);

/** One scan record. */
enum class TextStatus : uint8_t {
    UNAVAILABLE = 0,         // snapshot/range never captured
    OK = 1,
    HASH_MISMATCH = 2,       // live != build-time expected
    DRIFTED = 3,             // live != JNI_OnLoad snapshot
};
const char* text_status_name(TextStatus s);

struct TextScan {
    TextStatus status_vs_expected;   // vs build-time hash
    TextStatus status_vs_snapshot;   // vs OnLoad snapshot
    uint8_t live[32];
    uint8_t snapshot[32];
    uint8_t expected[32];
    bool expected_known;             // true iff a non-empty expected hash was set
    size_t segment_bytes;
};

/**
 * Recomputes SHA-256 of the live `.text` segment and fills [out]
 * with the comparison result. Returns false only if the snapshot
 * was never captured (e.g. range map empty); callers treat false
 * as "G2 unavailable" rather than a clean signal.
 */
bool scan_text(TextScan* out);

}  // namespace dicore::native_integrity
