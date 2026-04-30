#pragma once

// Native-integrity module entry points. Owned by `art_integrity_jni.cpp`'s
// existing JNI_OnLoad — there's exactly one OnLoad in libdicore (intentional;
// see the kdoc on `art_integrity_jni.cpp`) and we slot in alongside the
// `art_integrity::initialize_*` calls.
//
// Each Gx milestone in NATIVE_INTEGRITY_DESIGN.md adds an `initialize_*`
// here; the JNI layer calls them in dependency order at OnLoad time and
// the runtime reads the resulting state on demand from the
// `NativeBridge.scan*` JNI methods.

#include <jni.h>

namespace dicore::native_integrity {

/** Sentinel returned by `nativeIntegrityProbe()` (G1 CTF flag). */
constexpr uint32_t kProbeAlive = 0xC0DE1170;

/**
 * G1 — captures libdicore's load address + RX range and pre-builds
 * the system-library range map. Safe to call from JNI_OnLoad
 * before any Java code runs. Idempotent: repeat calls are no-ops.
 *
 * G2..G7 attach their own initialize hooks here in dependency
 * order: G2's `.text` snapshot must run after the range map
 * captures libdicore's RX extent.
 */
void initialize(JNIEnv* env);

/** Live sentinel for the G1 CTF flag. */
uint32_t probe();

}  // namespace dicore::native_integrity
