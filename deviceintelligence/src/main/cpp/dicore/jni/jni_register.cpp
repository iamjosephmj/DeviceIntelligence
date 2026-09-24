// Spec 08 (Stage C) — dynamic JNI registration.
//
// The five native impls behind tech.thessemaj.deviceintelligence.dx.NativeBridge are no longer exported as
// `Java_tech_thessemaj_deviceintelligence_dx_K_*` symbols; they are internal hidden-visibility functions
// bound here at load time. Reading `nm -D libdicore.so` reveals only JNI_OnLoad —
// the name→implementation table lives inside this OLLVM-flattened registrar, not
// in .dynsym. Recovering which address serves NativeBridge.g now means defeating the
// obfuscation on this function first.
//
// This is NOT a second JNI_OnLoad (the library has exactly one, in
// art_integrity_jni.cpp); it is a helper that OnLoad calls. FindClass resolves
// "tech/thessemaj/deviceintelligence/dx/NativeBridge" through the classloader of the thread that ran
// System.loadLibrary — K's own static initializer — so the anchor is reachable.

#include "dicore/jni/jni_anchors.h"
#include "dicore/jni/jni_cache.hpp"
#include "dicore/platform/obf.h"  // DI_OBF_MAX
#include "dicore/platform/log.h"

#include <jni.h>

// (seed-decryptable) even when exec-page resolution fails.

namespace dicore {

// kNoBind_*: the strenc pass exempts these from digest binding
// (kFlagNever) so anchor registration survives even when exec-page
// resolution fails — load-critical strings must never be D-dependent.
static const char kNoBind_Class[] = "tech/thessemaj/deviceintelligence/dx/NativeBridge";
static const char kNoBind_n_r[] = "r";
static const char kNoBind_s_r[] = "()Z";
static const char kNoBind_n_g[] = "g";
static const char kNoBind_s_g[] = "(Ljava/lang/String;)Ljava/lang/String;";
static const char kNoBind_n_s[] = "s";
static const char kNoBind_s_s[] = "(Ljava/lang/Class;)V";
static const char kNoBind_n_e[] = "e";
static const char kNoBind_s_e[] = "(Ljava/lang/String;)Ljava/lang/String;";
static const char kNoBind_n_p[] = "p";
static const char kNoBind_s_p[] = "(Ljava/lang/String;)Z";
static const char kNoBind_n_c[] = "c";
static const char kNoBind_s_c[] =
    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";


DI_OBF_MAX
bool register_k_anchors(JNIEnv* env) {
    if (env == nullptr) return false;
    // B1: every JNI call below goes through the JNI_OnLoad snapshot of the
    // env function table, so a vtable patched after load cannot interpose
    // the anchor registration.
    const jni_cache::Cache& jc = jni_cache::static_cache();
    if (jc.fn[jni_cache::Slot::FindClass] == nullptr) return false;  // never captured
    jclass k = jni_cache::get<jni_cache::Slot::FindClass, jni_cache::findclass_fn>(jc)(
            env, kNoBind_Class);
    if (k == nullptr) {
        jni_cache::get<jni_cache::Slot::ExceptionClear, jni_cache::exceptionclear_fn>(jc)(env);
        return false;
    }
    const JNINativeMethod methods[] = {
        {kNoBind_n_r, kNoBind_s_r, reinterpret_cast<void*>(anchors::nat_liveness)},
        {kNoBind_n_g, kNoBind_s_g, reinterpret_cast<void*>(anchors::nat_gated_key)},
        {kNoBind_n_s, kNoBind_s_s, reinterpret_cast<void*>(anchors::nat_register_shim)},
        {kNoBind_n_e, kNoBind_s_e, reinterpret_cast<void*>(anchors::nat_enroll)},
        {kNoBind_n_p, kNoBind_s_p, reinterpret_cast<void*>(anchors::nat_prepare)},
        {kNoBind_n_c, kNoBind_s_c, reinterpret_cast<void*>(anchors::nat_challenge)},
    };
    jint rc = jni_cache::get<jni_cache::Slot::RegisterNatives, jni_cache::registernatives_fn>(jc)(
            env, k, methods, sizeof(methods) / sizeof(methods[0]));
    jni_cache::get<jni_cache::Slot::DeleteLocalRef, jni_cache::deletelocalref_fn>(jc)(env, k);
    return rc == 0;
}

}  // namespace dicore
