#pragma once

// F18 — frozen-method registry.
//
// The "frozen-method" set is the small list of JDK methods whose
// `ArtMethod->entry_point_from_quick_compiled_code_` value should
// not change during normal app execution. We snapshot their entry
// pointers at `JNI_OnLoad` and check them on every F18 evaluate.
//
// Two reasons a method is "frozen" (non-mutually-exclusive):
//
//   - **JNI native**: the method is declared `native` in the JDK,
//     so the JIT never recompiles it. The entry pointer is the
//     dispatch stub inside `libart.so` (e.g. `art_jni_dlsym_lookup`),
//     and stays inside libart for the process lifetime.
//
//   - **Boot-image AOT**: the method is precompiled into
//     `boot-framework.oat` at first-boot. The entry pointer lives
//     inside that mapped OAT file's RX segment and never moves
//     unless an attacker rewrites the `ArtMethod` slot itself.
//
// Both classes have stable entry pointers under normal operation,
// so any change to those pointers is real signal — not JIT noise.
//
// We deliberately stay away from "hot" JDK methods (e.g.
// `String.equals`, `Object.toString`) that ART would tier from
// interpreter -> JIT -> AOT during the app's lifetime. Their
// entry pointers legitimately move and would false-positive a
// naive diff.

#include <jni.h>
#include <cstdint>
#include <cstddef>

namespace dicore::art_integrity {

/**
 * Why we picked this method (drives the expected range in M3).
 *
 * `JNI_NATIVE`            — declared `native`. Entry stays in libart.
 * `INTERPRETER_OR_AOT`    — pure Java. Entry should be in libart's
 *                           interpreter-bridge slot or in a boot OAT.
 *                           Crucially, NOT JIT-recompiled in normal use.
 */
enum class MethodKind : uint8_t {
    JNI_NATIVE = 1,
    INTERPRETER_OR_AOT = 2,
};

enum class CallStyle : uint8_t {
    INSTANCE = 1,
    STATIC = 2,
    CONSTRUCTOR = 3,
};

/**
 * Compile-time descriptor for one frozen method. Only the strings
 * are stored at rest; the resolved `jclass` global ref and
 * `jmethodID` are kept alongside in [ResolvedMethod].
 */
struct FrozenMethodSpec {
    const char* class_name;        // JNI internal form: "java/lang/String"
    const char* method_name;       // "length", "<init>", "currentTimeMillis"
    const char* method_signature;  // JNI signature: "()I", "(I)I"
    CallStyle call_style;
    MethodKind kind;
    const char* short_id;          // Stable forensic identifier, e.g. "java.lang.String#length"
};

/**
 * Resolved counterpart populated by [initialize].
 *
 * `jmethodID` is opaque but stable for the class's lifetime; storing
 * the raw value is fine. `jclass` is a JNI object reference and must
 * be promoted to a global ref so it survives past `JNI_OnLoad`.
 *
 * `entry_point` is the value of `ArtMethod->entry_point_from_quick_compiled_code_`
 * at the time of resolution. Left at nullptr if the jmethodID is
 * INDEX-encoded (see `offsets.h::JniIdEncoding`) — those IDs can't
 * be cast to ArtMethod* and need to be skipped for direct field
 * reads.
 */
struct ResolvedMethod {
    const FrozenMethodSpec* spec;
    jclass clazz;        // global reference; NewGlobalRef on init.
    jmethodID method_id;
    void* entry_point;
    bool entry_point_readable;  // false for INDEX-encoded jmethodIDs
};

/** Number of entries in the registry. Compile-time constant. */
size_t registry_size();

/** The compile-time spec for entry [index] (0..registry_size()). */
const FrozenMethodSpec* spec_at(size_t index);

/**
 * Resolves every entry's `jclass` + `jmethodID`. Idempotent; calls
 * after the first are no-ops. Must be called from a context that
 * has a valid `JNIEnv` and where the JDK classes are already
 * loadable (`JNI_OnLoad` is the canonical home).
 *
 * Returns the number of entries that resolved successfully. A
 * partial failure (e.g. an OEM that stripped `Math.abs(int)`) is
 * logged at WARN and that entry is left with `clazz == nullptr`,
 * so downstream checks skip it gracefully instead of crashing.
 */
size_t initialize(JNIEnv* env);

/**
 * Read accessor for the resolved entry at [index]. Returns
 * `nullptr` if [index] is out of range or if the entry never
 * resolved (clazz is null). Safe to call from any thread once
 * [initialize] has returned.
 */
const ResolvedMethod* resolved_at(size_t index);

/**
 * Diagnostic counter — number of entries that resolved cleanly.
 * Used by the M1 CTF logging and by future evaluate()s to decide
 * whether the registry is healthy enough to run a scan.
 */
size_t resolved_count();

/**
 * Diagnostic counter — number of entries whose entry-point pointer
 * was successfully read at JNI_OnLoad. Less than [resolved_count]
 * by the count of INDEX-encoded jmethodIDs (currentTimeMillis,
 * nanoTime, Math.abs(int) on the devices we tested).
 */
size_t entry_point_readable_count();

}  // namespace dicore::art_integrity
