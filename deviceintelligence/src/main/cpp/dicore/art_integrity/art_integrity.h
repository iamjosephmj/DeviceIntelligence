#pragma once

// F18 — ART integrity detector (in-process ART manipulation).
//
// This header is the internal API the JNI bridge (in
// `art_integrity_jni.cpp`) consumes. It is intentionally minimal:
// JNI sees only the few entry points it needs, and every concrete
// vector check (Vector A entry-point snapshot, Vector C JNIEnv
// snapshot, Vector D inline-prologue check) lives in its own
// translation unit under this same `art_integrity/` directory.
//
// Milestone 0 only provides a `probe()` that confirms the module
// compiled and linked — used by the M0 CTF flag to verify the
// detector skeleton + native plumbing is end-to-end wired before
// M1 adds the frozen-method registry.

#include <cstdint>

namespace dicore::art_integrity {

/**
 * One-shot liveness probe. Returns a non-zero sentinel so the
 * Kotlin side can confirm the new translation unit was actually
 * linked into `libdicore.so`. Any return value other than
 * `kProbeAlive` (or a JNI failure) means the build glued the
 * module incorrectly.
 *
 * Real probes (snapshot, evaluate, classify) land here in M4-M8.
 */
constexpr uint32_t kProbeAlive = 0xF18A11FE;
uint32_t probe();

}  // namespace dicore::art_integrity
