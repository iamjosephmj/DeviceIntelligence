#include "jni_env_table.h"

#include "../log.h"
#include "../sha256.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

namespace dicore::art_integrity {

namespace {

const char* const kFunctionNames[kJniEnvWatched] = {
    "GetMethodID",
    "GetStaticMethodID",
    "RegisterNatives",
    "CallStaticIntMethod",
    "CallObjectMethod",
    "FindClass",
    "NewObject",
    "GetObjectClass",
};

// Helper: snapshots the eight JNIEnv function pointers into [out].
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
}

// Self-protected baseline storage, mirroring the snapshot.cpp
// pattern. Two mmap pages: one for the values (kJniEnvWatched
// pointers + padding to one page), one for the SHA-256 hash.
struct JniEnvStorage {
    void* values_page = nullptr;
    void* hash_page = nullptr;
    size_t page_size = 0;
};

JniEnvStorage g_storage;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes = sizeof(const void*) * kJniEnvWatched;

bool ensure_pages_allocated() {
    if (g_storage.values_page != nullptr) return true;
    g_storage.page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    if (g_storage.page_size == 0) g_storage.page_size = 4096;

    auto map_one = []() -> void* {
        void* p = ::mmap(nullptr, g_storage.page_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (p == MAP_FAILED) ? nullptr : p;
    };
    g_storage.values_page = map_one();
    if (!g_storage.values_page) {
        RLOGE("F18 Vector C: mmap values_page failed errno=%d", errno);
        return false;
    }
    {
        thread_local std::mt19937_64 rng(
            static_cast<uint64_t>(::getpid()) * 0xBF58476D1CE4E5B9ull);
        const int spacers = static_cast<int>(rng() % 8);
        for (int i = 0; i < spacers; ++i) {
            void* spacer = ::mmap(nullptr, g_storage.page_size,
                                  PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                                  -1, 0);
            (void)spacer;
        }
    }
    g_storage.hash_page = map_one();
    if (!g_storage.hash_page) {
        ::munmap(g_storage.values_page, g_storage.page_size);
        g_storage.values_page = nullptr;
        RLOGE("F18 Vector C: mmap hash_page failed errno=%d", errno);
        return false;
    }
    std::memset(g_storage.values_page, 0, g_storage.page_size);
    std::memset(g_storage.hash_page, 0, g_storage.page_size);
    RLOGI("F18 Vector C: mmapped values=%p hash=%p (page=%zu)",
          g_storage.values_page, g_storage.hash_page, g_storage.page_size);
    return true;
}

bool unprotect_pages() {
    if (!g_storage.values_page || !g_storage.hash_page) return false;
    if (::mprotect(g_storage.values_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) {
        return false;
    }
    if (::mprotect(g_storage.hash_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) {
        ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
        return false;
    }
    return true;
}

void reprotect_pages() {
    if (!g_storage.values_page || !g_storage.hash_page) return;
    ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
    ::mprotect(g_storage.hash_page, g_storage.page_size, PROT_NONE);
}

// One-shot self-verification: after the first scan, re-reads
// /proc/self/maps and confirms our two pages are listed with
// `---p` (PROT_NONE). The log line is the M7 CTF evidence that
// Vector C's storage gets the same self-protection treatment as
// Vector A's snapshot. Runs once per process.
void log_jni_env_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[4096];
    char values_perms[8] = "?";
    char hash_perms[8] = "?";
    const auto values_addr =
        reinterpret_cast<uintptr_t>(g_storage.values_page);
    const auto hash_addr =
        reinterpret_cast<uintptr_t>(g_storage.hash_page);
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (std::sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
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
    std::fclose(f);
    RLOGI("F18 Vector C audit: values@%p perms=%s, hash@%p perms=%s (expected ---p / ---p)",
          g_storage.values_page, values_perms, g_storage.hash_page, hash_perms);
}

bool recompute_and_verify_hash() {
    uint8_t recomputed[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, recomputed)) {
        RLOGW("F18 Vector C: sha256 backend unavailable; treating as intact");
        return true;
    }
    return std::memcmp(recomputed, g_storage.hash_page, sha::kDigestLen) == 0;
}

void store_hash_for_current_values() {
    uint8_t digest[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, digest)) {
        RLOGW("F18 Vector C: sha256 backend unavailable; storing zero hash");
    }
    std::memcpy(g_storage.hash_page, digest, sha::kDigestLen);
}

}  // namespace

void initialize_jni_env(JNIEnv* env) {
    if (!env) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    if (!ensure_pages_allocated()) return;
    if (!unprotect_pages()) return;

    auto* values = static_cast<const void**>(g_storage.values_page);
    capture_pointers(env, values);
    for (size_t i = kJniEnvWatched; i < g_storage.page_size / sizeof(const void*); ++i) {
        values[i] = nullptr;
    }
    store_hash_for_current_values();
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
    reprotect_pages();
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
    if (!ensure_pages_allocated()) return 0;
    if (!unprotect_pages()) return 0;

    auto* values = static_cast<const void**>(g_storage.values_page);
    bool intact = recompute_and_verify_hash();

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
        store_hash_for_current_values();
        RLOGW("F18 Vector C: baseline tampered — recaptured");
    }

    reprotect_pages();
    log_jni_env_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_jni_env_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
