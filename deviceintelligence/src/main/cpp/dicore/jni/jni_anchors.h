#pragma once

// Spec 08 (Stage C) — the five native impls behind the tech.thessemaj.deviceintelligence.dx.NativeBridge anchor are
// no longer exported as `Java_tech_thessemaj_deviceintelligence_dx_K_*` symbols. They are plain internal
// (hidden-visibility) functions, bound at load time by RegisterNatives in
// jni_register.cpp's JNI_OnLoad. Net effect: `nm -D libdicore.so` no longer lists
// a single self-describing entry point — the only export left is JNI_OnLoad, and
// the name→address mapping lives inside an OLLVM-obfuscated registrar instead of
// the dynamic symbol table. An attacker can no longer grep the export table for
// "the key function".
//
// Signatures mirror K.kt's `external fun r/o/k/g/s`. JNICALL is a no-op on the
// shipped 64-bit ABIs but kept for calling-convention correctness.

#include <jni.h>

namespace dicore {
namespace anchors {

jboolean JNICALL nat_liveness(JNIEnv*, jclass);                 // NativeBridge.r — liveness
jstring  JNICALL nat_gated_key(JNIEnv*, jclass, jstring);        // NativeBridge.g — sweep-gated key
void     JNICALL nat_register_shim(JNIEnv*, jclass, jclass);         // NativeBridge.s — register shim
jstring  JNICALL nat_enroll(JNIEnv*, jclass, jstring);                   // NativeBridge.e — initialize() -> licence validation ("1"/"")
jboolean JNICALL nat_prepare(JNIEnv*, jclass, jstring);                  // NativeBridge.p — setSession(id): attest ONCE, cache in-process
jstring  JNICALL nat_challenge(JNIEnv*, jclass, jstring, jstring, jstring); // NativeBridge.c — challenge(sessionId, name, challenge) -> token

}  // namespace anchors

// Bind the five anchors onto tech.thessemaj.deviceintelligence.dx.NativeBridge via RegisterNatives. Called once from
// the library's single JNI_OnLoad (art_integrity_jni.cpp). The body is OLLVM-
// flattened so the name→implementation table is not a plain readable structure.
// Returns true on success; false leaves the natives unbound (fail-soft).
bool register_k_anchors(JNIEnv* env);

}  // namespace dicore
