#include "dicore/detectors/art_integrity/checks/jni_env_table.h"

#include "dicore/platform/log.h"
#include "dicore/platform/svc_io.h"
#include "dicore/crypto/sha256.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

#include "dicore/platform/protected_store.h"

namespace dicore::art_integrity {

namespace {

// The three string/static-call slots are the fix-wave extension: the token
// path (jstr / NewStringUTF emissions / shim string marshalling) rides the
// B1 jni_cache snapshot, so a late hook there is interposition-proof — but
// the framework shim's static up-calls (GetStaticMethodID /
// CallStaticObjectMethod) have no cache slots and stay on the live table, so
// a late hook on those (or on the string slots, against any unwired caller)
// must TRIP this watch instead.
const char* const kFunctionNames[kJniEnvWatched] = {
    "GetMethodID",
    "GetStaticMethodID",
    "RegisterNatives",
    "CallStaticIntMethod",
    "CallObjectMethod",
    "FindClass",
    "NewObject",
    "GetObjectClass",
    "NewStringUTF",
    "GetStringUTFChars",
    "CallStaticObjectMethod",
};

// Helper: snapshots the watched JNIEnv function pointers into [out].
// Reads through `(*env)->functions->...` so an attacker who's
// merely swapped JNIEnv on this thread gets caught.
void capture_pointers(JNIEnv* env, const void** out) {
    const JNINativeInterface* f = env->functions;
    out[0] = reinterpret_cast<const void*>(f->GetMethodID);
    out[1] = reinterpret_cast<const void*>(f->GetStaticMethodID);
    out[2] = reinterpret_cast<const void*>(f->RegisterNatives);
    out[3] = reinterpret_cast<const void*>(f->CallStaticIntMethod);
    out[4] = reinterpret_cast<const void*>(f->CallObjectMethod);
    out[5] = reinterpret_cast<const void*>(f->FindClass);
    out[6] = reinterpret_cast<const void*>(f->NewObject);
    out[7] = reinterpret_cast<const void*>(f->GetObjectClass);
    out[8] = reinterpret_cast<const void*>(f->NewStringUTF);
    out[9] = reinterpret_cast<const void*>(f->GetStringUTFChars);
    out[10] = reinterpret_cast<const void*>(f->CallStaticObjectMethod);
}

// Self-protected baseline storage, mirroring the snapshot.cpp
// pattern. Two mmap pages: one for the values (kJniEnvWatched
// pointers + padding to one page), one for the SHA-256 hash.
ProtectedStore g_store;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes = sizeof(const void*) * kJniEnvWatched;

// One-shot self-verification: after the first scan, re-reads
// /proc/self/maps and confirms our two pages are listed with
// `---p` (PROT_NONE). The log line is the M7 CTF evidence that
// Vector C's storage gets the same self-protection treatment as
// Vector A's snapshot. Runs once per process.
void log_jni_env_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    std::string maps;
    if (!svc::read_file("/proc/self/maps", &maps)) return;
    char values_perms[8] = "?";
    char hash_perms[8] = "?";
    const auto values_addr =
        reinterpret_cast<uintptr_t>(g_store.values_page());
    const auto hash_addr =
        reinterpret_cast<uintptr_t>(g_store.hash_page());
    svc::LineCursor cur(maps);
    std::string line;
    while (cur.next(&line)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (std::sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        // Accept "address falls within range": if both pages
        // happened to land adjacent with identical perms, the
        // kernel folds them into a single VMA whose start is
        // the lower of the two — using `>=` covers that case
        // without false-matching neighbouring mappings.
        if (values_addr >= start && values_addr < end) {
            std::strncpy(values_perms, perms, sizeof(values_perms) - 1);
        }
        if (hash_addr >= start && hash_addr < end) {
            std::strncpy(hash_perms, perms, sizeof(hash_perms) - 1);
        }
    }
    RLOGI("F18 Vector C audit: values@%p perms=%s, hash@%p perms=%s (expected ---p / ---p)",
          g_store.values_page(), values_perms, g_store.hash_page(), hash_perms);
}

}  // namespace

void initialize_jni_env(JNIEnv* env) {
    if (!env) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    if (!g_store.init(kBaselineValuesBytes)) return;
    if (!g_store.unprotect()) return;

    auto* values = static_cast<const void**>(g_store.values());
    capture_pointers(env, values);
    // The rest of the value region is already zero (ProtectedStore::init zeroed it).
    g_store.rehash();
    // Log the captured pointers BEFORE reprotect — once PROT_NONE
    // is set, dereferencing values[i] SIGSEGVs. This trace is the
    // M7 CTF flag (one line per watched function with its
    // snapshot address + classification).
    for (size_t i = 0; i < kJniEnvWatched; ++i) {
        Classification c = classify(values[i]);
        RLOGI("F18 Vector C snap[%zu] %-22s = %p (%s)",
              i, kFunctionNames[i], values[i], classification_name(c));
    }
    g_baseline_set.store(true, std::memory_order_release);
    g_store.reprotect();
    RLOGI("F18 Vector C: snapshot captured at JNI_OnLoad");
}

size_t scan_jni_env(JNIEnv* env, JniEnvScanEntry* out, size_t out_capacity) {
    if (!env || !out || out_capacity == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_baseline_set.load(std::memory_order_acquire)) {
        // No snapshot captured (initialize_jni_env was never
        // called). Treat as no-op to avoid false-positives.
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }
    if (!g_store.init(kBaselineValuesBytes)) return 0;
    if (!g_store.unprotect()) return 0;

    auto* values = static_cast<const void**>(g_store.values());
    bool intact = g_store.intact();

    const void* live[kJniEnvWatched] = {};
    capture_pointers(env, live);

    const size_t n = (kJniEnvWatched < out_capacity) ? kJniEnvWatched : out_capacity;
    for (size_t i = 0; i < n; ++i) {
        JniEnvScanEntry& e = out[i];
        e.function_name = kFunctionNames[i];
        e.snapshot_fn = intact ? values[i] : live[i];
        e.live_fn = live[i];
        e.snapshot_class = classify(e.snapshot_fn);
        e.live_class = classify(e.live_fn);
        e.drifted = intact && (e.live_fn != e.snapshot_fn);
    }

    if (!intact) {
        // Recapture so the next scan has a fresh, intact baseline.
        for (size_t i = 0; i < kJniEnvWatched; ++i) values[i] = live[i];
        g_store.rehash();
        RLOGW("F18 Vector C: baseline tampered — recaptured");
    }

    g_store.reprotect();
    log_jni_env_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_jni_env_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
