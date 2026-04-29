#pragma once

// F18 — Vector D: inline-prologue check on ART hot-path functions.
//
// Modern Frida (`Interceptor.attach`) hooks libart-internal C++
// functions by patching the target function's prologue with a
// branch-to-trampoline. The first ~16 bytes are the typical
// patch site:
//
//   - On arm64 Frida emits a 16-byte `LDR x16, [pc, #8]; BR x16; <abs64>`
//     pattern (or 4-byte `B #imm26` for in-range jumps).
//   - On x86_64 Frida emits a 5-byte `JMP rel32` or 12-byte
//     `MOV rax, abs64; JMP rax`.
//
// In every case, the overwritten bytes differ from the original
// instruction encoding, so a byte-wise compare against a snapshot
// captured at JNI_OnLoad reliably catches the patch.
//
// Targets are well-known assembly stubs exported by libart.so
// (`art_quick_invoke_stub`, `art_jni_dlsym_lookup_stub`, …). We
// resolve them via `dlsym` against the libart handle returned by
// `dlopen("libart.so", RTLD_NOLOAD)`. Symbols that don't resolve
// (renamed in a future Android version, hidden in a custom OEM
// build) are simply skipped — the check degrades gracefully.
//
// Storage mirrors Vector A and Vector C: the snapshot bytes plus
// their SHA-256 live in two separately-allocated `mmap` pages,
// kept at PROT_NONE between scans, and only briefly unprotected
// during read/compare.

#include <jni.h>

#include <cstddef>
#include <cstdint>

namespace dicore::art_integrity {

/** Number of bytes captured per target. 16 covers Frida's largest
 * inline trampoline encoding on both arm64 and x86_64. */
constexpr size_t kPrologueBytes = 16;

/** Maximum number of libart symbols Vector D will track. Sized
 * to fit the symbol list plus a small headroom; unresolved
 * slots are left empty. */
constexpr size_t kInlineMaxTargets = 16;

/** State of one prologue target after a scan. */
struct InlinePrologueScanEntry {
    const char* symbol;          // dlsym'd name; nullptr means slot unused
    const void* addr;            // resolved libart address, nullptr if dlsym failed
    uint8_t live[kPrologueBytes];
    uint8_t snapshot[kPrologueBytes];
    bool resolved;               // false → no dlsym hit; skip in finding emission
    bool drifted;                // true if live != snapshot
    bool baseline_known;         // true if an embedded baseline exists for this API+symbol
    bool baseline_mismatch;      // true if live differs from the embedded baseline
};

/**
 * Resolve every target symbol from libart and capture the
 * snapshot of its first [kPrologueBytes] into a self-protected
 * mmap page. Idempotent. Called from `JNI_OnLoad` so the
 * snapshot precedes any post-load attacker.
 */
void initialize_inline_prologue();

/**
 * Re-reads each resolved target's first [kPrologueBytes] live,
 * verifies the snapshot page, runs both compares (live-vs-
 * snapshot for drift, live-vs-embedded-baseline when known),
 * and writes one entry per slot into [out]. Returns the number
 * of slots written (always [kInlineMaxTargets] once the unit
 * is initialised, even when individual slots are unresolved —
 * Kotlin filters by `resolved`).
 */
size_t scan_inline_prologue(InlinePrologueScanEntry* out, size_t out_capacity);

/**
 * Returns true if the protected snapshot's hash matched its
 * stored value on the most recent scan. False means an attacker
 * tampered with the snapshot page between scans.
 */
bool last_inline_baseline_intact();

/**
 * Development-time helper: returns a String[] where each
 * element is `"<symbol>|<api_int>|<hex_bytes>"` for every
 * RESOLVED target. Used once on a clean device to harvest
 * prologue baselines for embedding in this file's `kBaselines`
 * table. Safe to call at any time; no protected storage is
 * touched.
 *
 * Runs on the JNI side via
 * `NativeBridge.artIntegrityExtractPrologueBaseline()` — the
 * JNI surface is otherwise unused at runtime.
 */
JNIEXPORT jobjectArray JNICALL extract_baseline_dump(JNIEnv* env);

}  // namespace dicore::art_integrity
