#pragma once

// B1 — JNIEnv vtable snapshot cache (.bss).
//
// Frida-Java's hooking machinery rewrites pointers inside the process-wide
// JNINativeInterface table (the vtable JNIEnv->functions points at). Bridge
// code that keeps calling `env->FindClass(...)` reads that (patchable) table
// on every call — a hook landed AFTER JNI_OnLoad silently interposes all of
// our JNI traffic (late env-hooking).
//
// This cache defeats that FOR THE WIRED PATH: at JNI_OnLoad start we copy
// the 16 function pointers we care about into a fixed .bss struct and every
// cache-wired call (anchor registration, the token/enroll string path) goes
// through the snapshot, not the live table. Honest limits: a PRE-load hook
// (zygisk-class, landed before JNI_OnLoad) snapshots the already-patched
// table, and the framework shim's static-call sites (GetStaticMethodID /
// CallStaticObjectMethod — no slots here) stay on the live table; those are
// covered by the F18 Vector C env-table watch instead — see the so-hardening
// ledger. Reading the vtable is a plain pointer copy — the table pages are
// readable, no mprotect needed (unlike the SIG capture rig, which WRITES and
// must flip page perms).
//
// Read-path obfuscation: cache indices are not read as plain constants. Each
// read goes through resolve(), which decodes a cookie-encoded table word
// (slot = (word - COOKIE) mod 16) — material for the MBA/OLLVM pass and a
// speed bump for static analysis even before that pass runs.
//
// Layout note: the JNI spec orders the table entries; our compact Slot enum
// does not match that order. capture_impl() maps Slot -> flat table index
// (kFlat, compile-time verified against the real jni.h on Android builds via
// offsetof static_asserts, and pinned by the host test's independently
// transcribed layout).

#include <cstdint>

namespace dicore::jni_cache {

enum Slot : uint32_t {
    FindClass = 0,
    GetMethodID = 1,
    RegisterNatives = 2,
    NewGlobalRef = 3,
    DeleteLocalRef = 4,
    CallObjectMethod = 5,
    NewStringUTF = 6,
    GetStringUTFChars = 7,
    ReleaseStringUTFChars = 8,
    ExceptionCheck = 9,
    ExceptionClear = 10,
    GetJavaVM = 11,
    GetArrayLength = 12,
    GetByteArrayElements = 13,
    ReleaseByteArrayElements = 14,
    AllocObject = 15,
};

struct Cache {
    void* fn[16];
};

// Cookie for MBA-indexed slot reads. Low nibble is zero so the encoded word
// is COOKIE + slot and the decode is (word - COOKIE) mod 16.
constexpr uint32_t kCookie = 0xC00C1E00u;

// Sentinel returned by resolve() for words that are not canonical encodings.
constexpr uint32_t kInvalid = 0xFFFFu;

// Decodes a cookie-encoded table word to its slot index. Only canonical
// words (== kCookie + slot) resolve; everything else yields kInvalid.
uint32_t resolve(uint32_t table_word);

// Core capture: copies the 16 watched entries from a table laid out like
// JNINativeInterface (flat spec order) into the compact Cache slots. Pure
// logic — host-testable with a fake void** table, no JNIEnv required.
void capture_impl(void** vt, Cache& c);

// The process-wide snapshot. Zero (.bss) until initialize() captures it.
Cache& static_cache();

// Typed read: compile-time slot -> typed function pointer, through the
// cookie-decoded index. Fn must match the real vtable entry's signature.
template <Slot S, typename Fn>
inline Fn get(const Cache& c) {
    static_assert(static_cast<uint32_t>(S) < 16u, "slot out of range");
    return reinterpret_cast<Fn>(c.fn[resolve(kCookie + static_cast<uint32_t>(S))]);
}

}  // namespace dicore::jni_cache

// The JNIEnv-facing surface exists only where a jni.h is available (every
// Android build; a host with JDK headers also gets it). The host unit-test
// toolchain has no jni.h, which keeps the core above the only part compiled
// there.
#if __has_include(<jni.h>)
#include <jni.h>
#define DICORE_JNI_CACHE_HAS_JNI 1
#endif

#ifdef DICORE_JNI_CACHE_HAS_JNI

namespace dicore::jni_cache {

// Function-pointer types mirroring the real JNINativeInterface entries.
using findclass_fn               = jclass (*)(JNIEnv*, const char*);
using getmethodid_fn             = jmethodID (*)(JNIEnv*, jclass, const char*, const char*);
using registernatives_fn         = jint (*)(JNIEnv*, jclass, const JNINativeMethod*, jint);
using newglobalref_fn            = jobject (*)(JNIEnv*, jobject);
using deletelocalref_fn          = void (*)(JNIEnv*, jobject);
using callobjectmethod_fn        = jobject (*)(JNIEnv*, jobject, jmethodID, ...);
using newstringutf_fn            = jstring (*)(JNIEnv*, const char*);
using getstringutfchars_fn       = const char* (*)(JNIEnv*, jstring, jboolean*);
using releasestringutfchars_fn   = void (*)(JNIEnv*, jstring, const char*);
using exceptioncheck_fn          = jboolean (*)(JNIEnv*);
using exceptionclear_fn          = void (*)(JNIEnv*);
using getjavavm_fn               = jint (*)(JNIEnv*, JavaVM**, jsize);
using getarraylength_fn          = jsize (*)(JNIEnv*, jarray);
using getbytearrayelements_fn    = jbyte* (*)(JNIEnv*, jbyteArray, jboolean*);
using releasebytearrayelements_fn = void (*)(JNIEnv*, jbyteArray, jbyte*, jint);
using allocobject_fn             = jobject (*)(JNIEnv*, jclass);

// One-line shim over capture_impl: the live env's function table viewed as
// the flat void** the core copies from.
void capture(JNIEnv* env, Cache& c);

// One-time capture into static_cache(). Called at JNI_OnLoad start, before
// any bridge call site can run. Idempotent.
void initialize(JNIEnv* env);

}  // namespace dicore::jni_cache

#endif  // DICORE_JNI_CACHE_HAS_JNI
