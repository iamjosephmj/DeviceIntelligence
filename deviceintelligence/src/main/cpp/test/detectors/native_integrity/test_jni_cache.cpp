// deviceintelligence/src/main/cpp/test/detectors/native_integrity/test_jni_cache.cpp
// Host test for the JNIEnv vtable snapshot cache (B1). No JNIEnv needed:
// capture_impl() is driven with a fake void** table that mirrors the real
// JNINativeInterface flat layout (verified against the NDK r27/r29 jni.h —
// byte-identical headers), and resolve()/get<> are pure logic.
#include <cstdio>
#include <cstdint>
#include "dicore/jni/jni_cache.hpp"

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main() {
    using namespace dicore::jni_cache;

    // The 16 watched entries at their flat positions inside JNINativeInterface,
    // in Slot order (FindClass=0 .. AllocObject=15). Transcribed from the JNI
    // table order in the NDK's jni.h; if jni_cache's flat map ever drifts from
    // the real header layout this CHECK fails even though the host never sees a
    // JNIEnv.
    const uint32_t kFlat[16] = {
        6,    // Slot::FindClass
        33,   // Slot::GetMethodID
        215,  // Slot::RegisterNatives
        21,   // Slot::NewGlobalRef
        23,   // Slot::DeleteLocalRef
        34,   // Slot::CallObjectMethod
        167,  // Slot::NewStringUTF
        169,  // Slot::GetStringUTFChars
        170,  // Slot::ReleaseStringUTFChars
        228,  // Slot::ExceptionCheck
        17,   // Slot::ExceptionClear
        219,  // Slot::GetJavaVM
        171,  // Slot::GetArrayLength
        184,  // Slot::GetByteArrayElements
        192,  // Slot::ReleaseByteArrayElements
        27,   // Slot::AllocObject
    };

    // --- static cache is .bss-zeroed and a stable singleton ---
    CHECK(&static_cache() == &static_cache());
    for (uint32_t s = 0; s < 16; ++s) CHECK(static_cache().fn[s] == nullptr);

    // --- capture_impl: slot mapping against a fake vtable mirroring the
    //     real JNINativeInterface layout (junk everywhere, marker per slot) ---
    // 233 = the REAL full table size (JNI entries 0..232, GetObjectRefType
    // last) — the fake mirrors the whole table, not just past the highest
    // watched slot (ExceptionCheck @228).
    void* fake_vt[233];
    for (uint32_t i = 0; i < 233; ++i) fake_vt[i] = reinterpret_cast<void*>(0xDEAD0000ul + i);
    for (uint32_t s = 0; s < 16; ++s)
        fake_vt[kFlat[s]] = reinterpret_cast<void*>(0x1000ul + s);  // unique marker
    Cache c;
    capture_impl(fake_vt, c);
    for (uint32_t s = 0; s < 16; ++s)
        CHECK(c.fn[s] == reinterpret_cast<void*>(0x1000ul + s));

    // --- resolve(): cookie decode round-trip for every slot ---
    for (uint32_t s = 0; s < 16; ++s) CHECK(resolve(kCookie + s) == s);
    CHECK(resolve(kCookie) == 0u);
    CHECK(resolve(kCookie + 15u) == 15u);

    // --- resolve(): non-canonical / out-of-range words -> 0xFFFF sentinel ---
    CHECK(resolve(kCookie + 16u) == 0xFFFFu);   // just past the slot range
    CHECK(resolve(kCookie + 31u) == 0xFFFFu);   // same mod-16 class, non-canonical
    CHECK(resolve(kCookie - 1u) == 0xFFFFu);    // below the cookie (wraps huge)
    CHECK(resolve(0u) == 0xFFFFu);
    CHECK(resolve(0xFFFFFFFFu) == 0xFFFFu);

    // --- get<>: typed fn pointer via the cookie-decoded read path ---
    using dummy_fn = int (*)(int);
    c.fn[Slot::FindClass] = reinterpret_cast<void*>(0x2000ul);
    c.fn[Slot::ExceptionClear] = reinterpret_cast<void*>(0x2001ul);
    dummy_fn ffc = get<Slot::FindClass, dummy_fn>(c);
    dummy_fn fec = get<Slot::ExceptionClear, dummy_fn>(c);
    CHECK(ffc == reinterpret_cast<dummy_fn>(static_cast<uintptr_t>(0x2000ul)));
    CHECK(fec == reinterpret_cast<dummy_fn>(static_cast<uintptr_t>(0x2001ul)));
    CHECK(ffc != fec);  // template picks the right slot

    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
