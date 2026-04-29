#include "registry.h"

#include "../log.h"
#include "offsets.h"
#include "ranges.h"

#include <android/api-level.h>
#include <atomic>

namespace dicore::art_integrity {

namespace {

// Curated list of "frozen" JDK methods. Each one is in here for a
// reason that's noted in the in-line comment — adding or removing
// entries should explain why the new method's entry pointer is
// (or isn't) immune to legitimate JIT/AOT churn.
//
// Picked deliberately small (10) to keep evaluate() cost trivial
// and to keep the per-Android-version maintenance burden bounded.
// Every entry has been stable across API 28-36 in our testing.
constexpr FrozenMethodSpec kSpecs[] = {
    // System.currentTimeMillis: declared `native`, the canonical
    // wall-clock entry point. Hooked by every Frida tutorial ever
    // written, so it's the single most-attacked method.
    {
        "java/lang/System", "currentTimeMillis", "()J",
        CallStyle::STATIC, MethodKind::JNI_NATIVE,
        "java.lang.System#currentTimeMillis",
    },
    // System.nanoTime: same shape, different entry point — picking
    // both gives independent witness if a hooker only patches one.
    {
        "java/lang/System", "nanoTime", "()J",
        CallStyle::STATIC, MethodKind::JNI_NATIVE,
        "java.lang.System#nanoTime",
    },
    // Object.hashCode: declared `native`. ART installs a pre-baked
    // identity-hash JNI stub. Stable.
    {
        "java/lang/Object", "hashCode", "()I",
        CallStyle::INSTANCE, MethodKind::JNI_NATIVE,
        "java.lang.Object#hashCode",
    },
    // Object.getClass: declared `native`. ART has a fast-path JNI
    // stub. Stable.
    {
        "java/lang/Object", "getClass", "()Ljava/lang/Class;",
        CallStyle::INSTANCE, MethodKind::JNI_NATIVE,
        "java.lang.Object#getClass",
    },
    // Object.<init>: pure Java, but always AOT-compiled into the
    // boot image. Entry pointer lives in boot-framework.oat.
    {
        "java/lang/Object", "<init>", "()V",
        CallStyle::CONSTRUCTOR, MethodKind::INTERPRETER_OR_AOT,
        "java.lang.Object#<init>",
    },
    // String.length: pure Java, AOT-compiled in boot image. ART
    // even has an intrinsic for this — extra evidence the entry
    // pointer is well-known and stable.
    {
        "java/lang/String", "length", "()I",
        CallStyle::INSTANCE, MethodKind::INTERPRETER_OR_AOT,
        "java.lang.String#length",
    },
    // String.charAt(int): pure Java, AOT-compiled. Same shape as
    // length, different code path.
    {
        "java/lang/String", "charAt", "(I)C",
        CallStyle::INSTANCE, MethodKind::INTERPRETER_OR_AOT,
        "java.lang.String#charAt",
    },
    // String.isEmpty: trivial, AOT-compiled.
    {
        "java/lang/String", "isEmpty", "()Z",
        CallStyle::INSTANCE, MethodKind::INTERPRETER_OR_AOT,
        "java.lang.String#isEmpty",
    },
    // Math.abs(int): static, AOT-compiled. Also intrinsified.
    {
        "java/lang/Math", "abs", "(I)I",
        CallStyle::STATIC, MethodKind::INTERPRETER_OR_AOT,
        "java.lang.Math#abs(int)",
    },
    // Thread.currentThread: declared `native`. JNI stub in libart.
    {
        "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;",
        CallStyle::STATIC, MethodKind::JNI_NATIVE,
        "java.lang.Thread#currentThread",
    },
};

constexpr size_t kSpecCount = sizeof(kSpecs) / sizeof(kSpecs[0]);

ResolvedMethod g_resolved[kSpecCount] = {};
std::atomic<bool> g_initialized{false};
std::atomic<size_t> g_resolved_count{0};

// Pulls the right method-id resolver for the call style. Constructors
// look like instance methods to JNI but conventionally use GetMethodID
// with the literal "<init>" name and a void return signature, so
// they're indistinguishable from instance methods at the API level.
jmethodID resolve_method_id(JNIEnv* env, jclass clazz, const FrozenMethodSpec& spec) {
    switch (spec.call_style) {
        case CallStyle::STATIC:
            return env->GetStaticMethodID(clazz, spec.method_name, spec.method_signature);
        case CallStyle::INSTANCE:
        case CallStyle::CONSTRUCTOR:
            return env->GetMethodID(clazz, spec.method_name, spec.method_signature);
    }
    return nullptr;
}

}  // namespace

size_t registry_size() {
    return kSpecCount;
}

const FrozenMethodSpec* spec_at(size_t index) {
    if (index >= kSpecCount) return nullptr;
    return &kSpecs[index];
}

size_t initialize(JNIEnv* env) {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) {
        return g_resolved_count.load(std::memory_order_acquire);
    }
    const int api = android_get_device_api_level();
    const size_t entry_offset = entry_point_offset(api);
    RLOGI("F18 registry: SDK_INT=%d entry_point_offset=0x%zx", api, entry_offset);

    // Build the address-range catalog before we read any entry
    // pointers so the logging below can label each address with
    // its expected region. Doing it here (instead of lazily on
    // first classify()) keeps every M3 log line in one cluster
    // and makes the JNI_OnLoad output one self-contained snapshot.
    initialize_ranges();

    size_t resolved = 0;
    for (size_t i = 0; i < kSpecCount; ++i) {
        const FrozenMethodSpec& spec = kSpecs[i];
        ResolvedMethod& slot = g_resolved[i];
        slot.spec = &spec;
        slot.clazz = nullptr;
        slot.method_id = nullptr;
        slot.entry_point = nullptr;
        slot.entry_point_readable = false;

        jclass local = env->FindClass(spec.class_name);
        if (!local) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            RLOGW("F18 registry: FindClass(%s) failed for %s",
                  spec.class_name, spec.short_id);
            continue;
        }
        // Promote to global ref so the class object survives across
        // JNI_OnLoad. Local refs are released the moment we return
        // from JNI; without the global, every entry's clazz would
        // become a dangling reference before the first evaluate().
        jclass global = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
        if (!global) {
            RLOGW("F18 registry: NewGlobalRef failed for %s", spec.short_id);
            continue;
        }

        jmethodID mid = resolve_method_id(env, global, spec);
        if (!mid) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            RLOGW("F18 registry: method resolve failed for %s (%s)",
                  spec.short_id, spec.method_signature);
            env->DeleteGlobalRef(global);
            continue;
        }

        slot.clazz = global;
        slot.method_id = mid;

        // M2: read the entry point now (single-shot) for later
        // milestones to snapshot. Skipped for INDEX-encoded IDs
        // because we'd be dereferencing an ART JNI-id-table index
        // as if it were a struct pointer — that's a wild read.
        const JniIdEncoding enc = classify_jni_id(mid);
        if (enc == JniIdEncoding::POINTER && entry_offset != kUnknownOffset) {
            slot.entry_point = read_entry_point(mid, entry_offset);
            slot.entry_point_readable = (slot.entry_point != nullptr);
        }
        ++resolved;
        const Classification cls = slot.entry_point != nullptr
            ? classify(slot.entry_point)
            : Classification::UNKNOWN;
        RLOGI("F18 registry: resolved %-40s mid=%p enc=%-7s entry=%p region=%-9s kind=%d",
              spec.short_id,
              static_cast<void*>(mid),
              enc == JniIdEncoding::POINTER ? "pointer" : "index",
              slot.entry_point,
              classification_name(cls),
              static_cast<int>(spec.kind));
    }
    g_resolved_count.store(resolved, std::memory_order_release);
    RLOGI("F18 registry: %zu/%zu methods resolved", resolved, kSpecCount);
    return resolved;
}

const ResolvedMethod* resolved_at(size_t index) {
    if (index >= kSpecCount) return nullptr;
    if (!g_initialized.load(std::memory_order_acquire)) return nullptr;
    const ResolvedMethod* r = &g_resolved[index];
    if (r->clazz == nullptr) return nullptr;
    return r;
}

size_t resolved_count() {
    return g_resolved_count.load(std::memory_order_acquire);
}

size_t entry_point_readable_count() {
    if (!g_initialized.load(std::memory_order_acquire)) return 0;
    size_t out = 0;
    for (size_t i = 0; i < kSpecCount; ++i) {
        if (g_resolved[i].entry_point_readable) ++out;
    }
    return out;
}

}  // namespace dicore::art_integrity
