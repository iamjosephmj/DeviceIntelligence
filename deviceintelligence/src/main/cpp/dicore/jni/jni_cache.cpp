#include "dicore/jni/jni_cache.hpp"

// See jni_cache.hpp for the threat model. The flat indices below are the
// declaration-order positions inside JNINativeInterface (JNI spec order);
// they are compile-time verified against the actual jni.h on Android builds
// and pinned by test_jni_cache.cpp on the host.

namespace dicore::jni_cache {

namespace {

// Slot -> flat index within JNINativeInterface. Verified against NDK r27
// (the pinned toolchain) and r29 — the headers are byte-identical.
constexpr uint32_t kFlat[16] = {
    6,    // FindClass
    33,   // GetMethodID
    215,  // RegisterNatives
    21,   // NewGlobalRef
    23,   // DeleteLocalRef
    34,   // CallObjectMethod
    167,  // NewStringUTF
    169,  // GetStringUTFChars
    170,  // ReleaseStringUTFChars
    228,  // ExceptionCheck
    17,   // ExceptionClear
    219,  // GetJavaVM
    171,  // GetArrayLength
    184,  // GetByteArrayElements
    192,  // ReleaseByteArrayElements
    27,   // AllocObject
};

}  // namespace

#ifdef __ANDROID__
// Compile-time proof that kFlat matches the jni.h this .so is built against:
// if a future NDK reorders the table, the build breaks instead of the cache
// silently capturing the wrong functions.
#define DICORE_JNI_FLAT_CHECK(member, idx)                                    \
    static_assert(                                                           \
        __builtin_offsetof(JNINativeInterface, member) == (idx) * sizeof(void*), \
        "jni.h flat index mismatch for " #member)
DICORE_JNI_FLAT_CHECK(FindClass, 6);
DICORE_JNI_FLAT_CHECK(GetMethodID, 33);
DICORE_JNI_FLAT_CHECK(RegisterNatives, 215);
DICORE_JNI_FLAT_CHECK(NewGlobalRef, 21);
DICORE_JNI_FLAT_CHECK(DeleteLocalRef, 23);
DICORE_JNI_FLAT_CHECK(CallObjectMethod, 34);
DICORE_JNI_FLAT_CHECK(NewStringUTF, 167);
DICORE_JNI_FLAT_CHECK(GetStringUTFChars, 169);
DICORE_JNI_FLAT_CHECK(ReleaseStringUTFChars, 170);
DICORE_JNI_FLAT_CHECK(ExceptionCheck, 228);
DICORE_JNI_FLAT_CHECK(ExceptionClear, 17);
DICORE_JNI_FLAT_CHECK(GetJavaVM, 219);
DICORE_JNI_FLAT_CHECK(GetArrayLength, 171);
DICORE_JNI_FLAT_CHECK(GetByteArrayElements, 184);
DICORE_JNI_FLAT_CHECK(ReleaseByteArrayElements, 192);
DICORE_JNI_FLAT_CHECK(AllocObject, 27);
#undef DICORE_JNI_FLAT_CHECK
#endif  // __ANDROID__

uint32_t resolve(uint32_t table_word) {
    // MBA read-path decode: slot = (word - COOKIE) mod 16. Only canonical
    // encodings (word == COOKIE + slot, no high garbage) resolve; anything
    // else is out of range and yields the sentinel.
    const uint32_t d = table_word - kCookie;
    const uint32_t slot = d % 16u;
    return (d >> 4) == 0u ? slot : kInvalid;
}

void capture_impl(void** vt, Cache& c) {
    for (uint32_t s = 0; s < 16u; ++s) c.fn[s] = vt[kFlat[s]];
}

Cache& static_cache() {
    static Cache g_cache = {};  // zero-initialized -> .bss
    return g_cache;
}

#ifdef DICORE_JNI_CACHE_HAS_JNI

void capture(JNIEnv* env, Cache& c) {
    // const_cast: the table is only READ here; capture_impl takes void**
    // because the host-test fake table is non-const.
    capture_impl(reinterpret_cast<void**>(const_cast<JNINativeInterface*>(env->functions)), c);
}

void initialize(JNIEnv* env) {
    static bool captured = false;  // JNI_OnLoad runs under the loader lock
    if (env == nullptr || captured) return;
    capture(env, static_cache());
    captured = true;
}

#endif  // DICORE_JNI_CACHE_HAS_JNI

}  // namespace dicore::jni_cache
