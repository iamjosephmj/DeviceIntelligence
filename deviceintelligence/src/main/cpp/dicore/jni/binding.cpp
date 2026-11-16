#include "dicore/platform/obf.h"  // DI_OBF_MAX
#include "dicore/crypto/sha256.h"
#include "dicore/platform/string_gate.h"
#include "dicore/jni/jni_anchors.h"
#include "dicore/jni/jni_cache.hpp"

#include <jni.h>
#include <cstdint>
#include <cstring>

// Spec 04/07 — env-derived dex-string key (the sole surviving entry point here;
// the spec-05 functional-binding nativeSeal was removed with the deleted public
// bind() API).

namespace dicore {


namespace {
const char kHexDigits[] = "0123456789abcdef";

// key = SHA256( (seed ⊕ U) ⊕ SHA256("dicore-dexkey-mix-v1") ). U arrives from the
// string_gate (clean sweep). The unlock phrase is NOT in this TU, so NativeBridge.g cannot
// recompute U — only receive it. Nothing consumes the derived key any more;
// this entry survives as a prologue_verify anchor (see K.kt [g]).
DI_OBF_MAX __attribute__((noinline))
bool derive_dex_key_gated(const uint8_t* seed, const uint8_t u[32],
                           uint8_t out[sha::kDigestLen]) {
    if (!sha::ensure_initialized()) return false;
    const char* phrase = "dicore-dexkey-mix-v1";
    uint8_t mix[sha::kDigestLen];
    if (!sha::sha256(phrase, strlen(phrase), mix)) return false;
    uint8_t eff[sha::kDigestLen];
    for (size_t i = 0; i < sha::kDigestLen; ++i)
        eff[i] = (uint8_t)((seed[i] ^ u[i]) ^ mix[i]);
    return sha::sha256(eff, sha::kDigestLen, out);
}
} // namespace

DI_OBF_MAX
jstring JNICALL anchors::nat_gated_key(
        JNIEnv* env, jclass, jstring seedHexJ) {
    // B1: string marshalling through the JNI_OnLoad vtable snapshot.
    const jni_cache::Cache& jc = jni_cache::static_cache();
    const char* seedHex =
            jni_cache::get<jni_cache::Slot::GetStringUTFChars, jni_cache::getstringutfchars_fn>(jc)(
                    env, seedHexJ, nullptr);
    if (seedHex == nullptr)
        return jni_cache::get<jni_cache::Slot::NewStringUTF, jni_cache::newstringutf_fn>(jc)(env, "");
    uint8_t seed[sha::kDigestLen] = {0};
    size_t hexLen = strlen(seedHex);
    for (size_t i = 0; i < sha::kDigestLen && (2 * i + 1) < hexLen; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        seed[i] = (uint8_t)((nib(seedHex[2 * i]) << 4) | nib(seedHex[2 * i + 1]));
    }
    jni_cache::get<jni_cache::Slot::ReleaseStringUTFChars, jni_cache::releasestringutfchars_fn>(jc)(
            env, seedHexJ, seedHex);
    uint8_t u[32];
    string_gate_wait(u);                 // blocks until the clean sweep publishes
    uint8_t key[sha::kDigestLen];
    if (!derive_dex_key_gated(seed, u, key))
        return jni_cache::get<jni_cache::Slot::NewStringUTF, jni_cache::newstringutf_fn>(jc)(env, "");
    char hex[sha::kDigestLen * 2 + 1];
    for (size_t i = 0; i < sha::kDigestLen; ++i) {
        hex[2 * i] = kHexDigits[(key[i] >> 4) & 0xf];
        hex[2 * i + 1] = kHexDigits[key[i] & 0xf];
    }
    hex[sha::kDigestLen * 2] = '\0';
    return jni_cache::get<jni_cache::Slot::NewStringUTF, jni_cache::newstringutf_fn>(jc)(env, hex);
}

} // namespace dicore
