#include "jni_entry.h"

#include "../log.h"
#include "../sha256.h"
#include "offsets.h"
#include "ranges.h"
#include "registry.h"

#include <android/api-level.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

namespace dicore::art_integrity {

namespace {

// Cached `data_` / `entry_point_from_jni_` offset for the
// running Android API. Resolved once on first scan.
size_t cached_jni_entry_offset() {
    static const size_t kOffset =
        jni_entry_offset(android_get_device_api_level());
    return kOffset;
}

size_t cached_access_flags_offset() {
    return kAccessFlagsOffset;
}

// Mirrors snapshot.cpp's BaselineStorage but for the JNI-entry
// slot. Same protect/unprotect dance, same separately-mmapped
// hash page so the layout doesn't betray its purpose.
struct JniEntryStorage {
    void* values_page = nullptr;
    void* hash_page = nullptr;
    void* native_flags_page = nullptr;  // 1 byte per slot: was the method declared `native` in the JDK
                                        // (registry kind == JNI_NATIVE)? Stored at snapshot time so
                                        // the scan can apply the right drift filter without re-reading
                                        // the registry. Distinct from ACC_NATIVE which ART de-flags
                                        // for intrinsified methods (Object#hashCode etc).
    size_t page_size = 0;
};

JniEntryStorage g_storage;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes =
    sizeof(const void*) * kJniEntryMaxEntries;

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
        RLOGE("F18 Vector E: mmap values_page failed errno=%d", errno);
        return false;
    }
    {
        thread_local std::mt19937_64 rng(
            static_cast<uint64_t>(::getpid()) * 0x94D049BB133111EBull);
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
        RLOGE("F18 Vector E: mmap hash_page failed errno=%d", errno);
        return false;
    }
    g_storage.native_flags_page = map_one();
    if (!g_storage.native_flags_page) {
        ::munmap(g_storage.values_page, g_storage.page_size);
        ::munmap(g_storage.hash_page, g_storage.page_size);
        g_storage.values_page = nullptr;
        g_storage.hash_page = nullptr;
        RLOGE("F18 Vector E: mmap native_flags_page failed errno=%d", errno);
        return false;
    }
    std::memset(g_storage.values_page, 0, g_storage.page_size);
    std::memset(g_storage.hash_page, 0, g_storage.page_size);
    std::memset(g_storage.native_flags_page, 0, g_storage.page_size);
    RLOGI("F18 Vector E: mmapped values=%p hash=%p flags=%p (page=%zu)",
          g_storage.values_page, g_storage.hash_page,
          g_storage.native_flags_page, g_storage.page_size);
    return true;
}

bool unprotect_pages() {
    if (!g_storage.values_page || !g_storage.hash_page || !g_storage.native_flags_page) {
        return false;
    }
    if (::mprotect(g_storage.values_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) {
        return false;
    }
    if (::mprotect(g_storage.hash_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) {
        ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
        return false;
    }
    if (::mprotect(g_storage.native_flags_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) {
        ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
        ::mprotect(g_storage.hash_page, g_storage.page_size, PROT_NONE);
        return false;
    }
    return true;
}

void reprotect_pages() {
    if (!g_storage.values_page || !g_storage.hash_page || !g_storage.native_flags_page) {
        return;
    }
    ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
    ::mprotect(g_storage.hash_page, g_storage.page_size, PROT_NONE);
    ::mprotect(g_storage.native_flags_page, g_storage.page_size, PROT_NONE);
}

// Audit log: confirms the three pages are PROT_NONE on first
// scan. Mirrors the Vector C audit; runs once per process.
void log_jni_entry_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[4096];
    char vals_perms[8] = "?";
    char hash_perms[8] = "?";
    char flags_perms[8] = "?";
    const auto vals_addr =
        reinterpret_cast<uintptr_t>(g_storage.values_page);
    const auto hash_addr =
        reinterpret_cast<uintptr_t>(g_storage.hash_page);
    const auto flags_addr =
        reinterpret_cast<uintptr_t>(g_storage.native_flags_page);
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (std::sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (vals_addr >= start && vals_addr < end) {
            std::strncpy(vals_perms, perms, sizeof(vals_perms) - 1);
        }
        if (hash_addr >= start && hash_addr < end) {
            std::strncpy(hash_perms, perms, sizeof(hash_perms) - 1);
        }
        if (flags_addr >= start && flags_addr < end) {
            std::strncpy(flags_perms, perms, sizeof(flags_perms) - 1);
        }
    }
    std::fclose(f);
    RLOGI("F18 Vector E audit: values@%p perms=%s, hash@%p perms=%s, "
          "flags@%p perms=%s (expected ---p / ---p / ---p)",
          g_storage.values_page, vals_perms,
          g_storage.hash_page, hash_perms,
          g_storage.native_flags_page, flags_perms);
}

bool recompute_and_verify_hash() {
    uint8_t recomputed[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, recomputed)) {
        RLOGW("F18 Vector E: sha256 backend unavailable; treating as intact");
        return true;
    }
    return std::memcmp(recomputed, g_storage.hash_page, sha::kDigestLen) == 0;
}

void store_hash_for_current_values() {
    uint8_t digest[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, digest)) {
        RLOGW("F18 Vector E: sha256 backend unavailable; storing zero hash");
    }
    std::memcpy(g_storage.hash_page, digest, sha::kDigestLen);
}

}  // namespace

void initialize_jni_entry() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    if (!ensure_pages_allocated()) return;
    if (!unprotect_pages()) return;

    const size_t entry_off = cached_jni_entry_offset();
    (void)cached_access_flags_offset();  // kept for future use; bit watch lives in Vector F
    const size_t reg_size = registry_size();
    const size_t n = (reg_size < kJniEntryMaxEntries)
                         ? reg_size : kJniEntryMaxEntries;

    auto* values = static_cast<const void**>(g_storage.values_page);
    auto* native_flags = static_cast<uint8_t*>(g_storage.native_flags_page);

    for (size_t i = 0; i < n; ++i) {
        values[i] = nullptr;
        native_flags[i] = 0;
        const ResolvedMethod* slot = resolved_at(i);
        if (slot == nullptr) continue;
        if (entry_off == kUnknownOffset) continue;
        if (classify_jni_id(slot->method_id) != JniIdEncoding::POINTER) continue;

        // Snapshot data_ / entry_point_from_jni_.
        values[i] = read_entry_point(slot->method_id, entry_off);
        // Stamp the static method kind from the registry. Using
        // the JDK-declaration kind instead of the runtime
        // ACC_NATIVE bit is essential: ART intrinsifies some
        // declared-native methods (Object#hashCode and friends)
        // and clears their ACC_NATIVE bit, but the `data_` slot
        // still holds the JNI bridge pointer — so attacker drift
        // there is real signal even though the runtime bit reads
        // 0.
        native_flags[i] = (slot->spec->kind == MethodKind::JNI_NATIVE) ? 1 : 0;
    }
    // Zero the trailing slack so layout doesn't depend on
    // resolved-count (defence in depth against a memory-scanning
    // attacker).
    for (size_t i = n; i < kJniEntryMaxEntries; ++i) {
        values[i] = nullptr;
        native_flags[i] = 0;
    }

    store_hash_for_current_values();
    // CTF log line BEFORE reprotect: once PROT_NONE is set,
    // reading values[i] SIGSEGVs.
    for (size_t i = 0; i < n; ++i) {
        Classification c = classify(values[i]);
        const FrozenMethodSpec* spec = spec_at(i);
        RLOGI("F18 Vector E snap[%zu] %-40s data_=%p (%s) native_by_spec=%d",
              i, spec ? spec->short_id : "<unknown>",
              values[i], classification_name(c), native_flags[i]);
    }
    g_baseline_set.store(true, std::memory_order_release);
    reprotect_pages();
    RLOGI("F18 Vector E: snapshot captured at JNI_OnLoad (%zu slots)", n);
}

size_t scan_jni_entry(JniEntryScanEntry* out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_baseline_set.load(std::memory_order_acquire)) {
        // No snapshot — degrade silently.
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }
    if (!ensure_pages_allocated()) return 0;
    if (!unprotect_pages()) return 0;

    const size_t entry_off = cached_jni_entry_offset();
    if (entry_off == kUnknownOffset) {
        reprotect_pages();
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }

    auto* values = static_cast<const void**>(g_storage.values_page);
    auto* native_flags = static_cast<uint8_t*>(g_storage.native_flags_page);

    bool intact = recompute_and_verify_hash();

    const size_t reg_size = registry_size();
    const size_t n = (reg_size < out_capacity) ? reg_size : out_capacity;
    if (n > kJniEntryMaxEntries) {
        // Defensive cap; baseline is sized for kJniEntryMaxEntries.
        reprotect_pages();
        return 0;
    }

    void* live_values[kJniEntryMaxEntries] = {};
    for (size_t i = 0; i < n; ++i) {
        JniEntryScanEntry& e = out[i];
        e.short_id = nullptr;
        e.snapshot_entry = nullptr;
        e.live_entry = nullptr;
        e.snapshot_class = Classification::UNKNOWN;
        e.live_class = Classification::UNKNOWN;
        e.readable = false;
        e.drifted = false;
        e.is_native_by_spec = native_flags[i] != 0;

        const FrozenMethodSpec* spec = spec_at(i);
        const ResolvedMethod* slot = resolved_at(i);
        e.short_id = spec ? spec->short_id : "<unknown>";
        if (!slot) continue;
        if (classify_jni_id(slot->method_id) != JniIdEncoding::POINTER) continue;

        live_values[i] = read_entry_point(slot->method_id, entry_off);
        e.live_entry = live_values[i];
        e.live_class = e.live_entry != nullptr
                           ? classify(e.live_entry)
                           : Classification::UNKNOWN;
        e.readable = true;

        if (intact) {
            e.snapshot_entry = values[i];
            e.snapshot_class = e.snapshot_entry != nullptr
                                   ? classify(e.snapshot_entry)
                                   : Classification::UNKNOWN;
            e.drifted = (e.live_entry != e.snapshot_entry);
        } else {
            // Baseline tampered — recapture but report no drift
            // this round.
            e.snapshot_entry = e.live_entry;
            e.snapshot_class = e.live_class;
            e.drifted = false;
        }
    }

    if (!intact) {
        for (size_t i = 0; i < n; ++i) values[i] = live_values[i];
        for (size_t i = n; i < kJniEntryMaxEntries; ++i) values[i] = nullptr;
        store_hash_for_current_values();
        RLOGW("F18 Vector E: baseline tampered — recaptured");
    }

    reprotect_pages();
    log_jni_entry_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_jni_entry_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
