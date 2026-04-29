#include "access_flags.h"

#include "../log.h"
#include "../sha256.h"
#include "offsets.h"
#include "registry.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

namespace dicore::art_integrity {

namespace {

// Mirrors Vector E's storage. Values page holds
// `uint32_t access_flags_[kAccessFlagsMaxEntries]`, hash page
// holds the SHA-256 of those bytes.
struct AccessFlagsStorage {
    void* values_page = nullptr;
    void* hash_page = nullptr;
    size_t page_size = 0;
};

AccessFlagsStorage g_storage;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes =
    sizeof(uint32_t) * kAccessFlagsMaxEntries;

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
        RLOGE("F18 Vector F: mmap values_page failed errno=%d", errno);
        return false;
    }
    {
        thread_local std::mt19937_64 rng(
            static_cast<uint64_t>(::getpid()) * 0x2545F4914F6CDD1Dull);
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
        RLOGE("F18 Vector F: mmap hash_page failed errno=%d", errno);
        return false;
    }
    std::memset(g_storage.values_page, 0, g_storage.page_size);
    std::memset(g_storage.hash_page, 0, g_storage.page_size);
    RLOGI("F18 Vector F: mmapped values=%p hash=%p (page=%zu)",
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

void log_access_flags_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[4096];
    char vals_perms[8] = "?";
    char hash_perms[8] = "?";
    const auto vals_addr =
        reinterpret_cast<uintptr_t>(g_storage.values_page);
    const auto hash_addr =
        reinterpret_cast<uintptr_t>(g_storage.hash_page);
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
    }
    std::fclose(f);
    RLOGI("F18 Vector F audit: values@%p perms=%s, hash@%p perms=%s "
          "(expected ---p / ---p)",
          g_storage.values_page, vals_perms,
          g_storage.hash_page, hash_perms);
}

bool recompute_and_verify_hash() {
    uint8_t recomputed[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, recomputed)) {
        RLOGW("F18 Vector F: sha256 backend unavailable; treating as intact");
        return true;
    }
    return std::memcmp(recomputed, g_storage.hash_page, sha::kDigestLen) == 0;
}

void store_hash_for_current_values() {
    uint8_t digest[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, digest)) {
        RLOGW("F18 Vector F: sha256 backend unavailable; storing zero hash");
    }
    std::memcpy(g_storage.hash_page, digest, sha::kDigestLen);
}

}  // namespace

void initialize_access_flags() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    if (!ensure_pages_allocated()) return;
    if (!unprotect_pages()) return;

    auto* values = static_cast<uint32_t*>(g_storage.values_page);
    const size_t reg_size = registry_size();
    const size_t n = (reg_size < kAccessFlagsMaxEntries)
                         ? reg_size : kAccessFlagsMaxEntries;
    for (size_t i = 0; i < n; ++i) {
        values[i] = 0;
        const ResolvedMethod* slot = resolved_at(i);
        if (!slot) continue;
        if (classify_jni_id(slot->method_id) != JniIdEncoding::POINTER) continue;
        values[i] = read_u32_field(slot->method_id, kAccessFlagsOffset);
    }
    for (size_t i = n; i < kAccessFlagsMaxEntries; ++i) values[i] = 0;
    store_hash_for_current_values();

    for (size_t i = 0; i < n; ++i) {
        const FrozenMethodSpec* spec = spec_at(i);
        RLOGI("F18 Vector F snap[%zu] %-40s access_flags_=0x%08x (native=%d)",
              i, spec ? spec->short_id : "<unknown>",
              values[i], (values[i] & kAccNative) ? 1 : 0);
    }
    g_baseline_set.store(true, std::memory_order_release);
    reprotect_pages();
    RLOGI("F18 Vector F: snapshot captured at JNI_OnLoad (%zu slots)", n);
}

size_t scan_access_flags(AccessFlagsScanEntry* out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_baseline_set.load(std::memory_order_acquire)) {
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }
    if (!ensure_pages_allocated()) return 0;
    if (!unprotect_pages()) return 0;

    auto* values = static_cast<uint32_t*>(g_storage.values_page);
    bool intact = recompute_and_verify_hash();

    const size_t reg_size = registry_size();
    const size_t n = (reg_size < out_capacity) ? reg_size : out_capacity;
    if (n > kAccessFlagsMaxEntries) {
        reprotect_pages();
        return 0;
    }

    uint32_t live_values[kAccessFlagsMaxEntries] = {};
    for (size_t i = 0; i < n; ++i) {
        AccessFlagsScanEntry& e = out[i];
        e.short_id = nullptr;
        e.snapshot_flags = 0;
        e.live_flags = 0;
        e.readable = false;
        e.native_flipped_on = false;
        e.native_flipped_off = false;
        e.any_drift = false;

        const FrozenMethodSpec* spec = spec_at(i);
        const ResolvedMethod* slot = resolved_at(i);
        e.short_id = spec ? spec->short_id : "<unknown>";
        if (!slot) continue;
        if (classify_jni_id(slot->method_id) != JniIdEncoding::POINTER) continue;

        live_values[i] = read_u32_field(slot->method_id, kAccessFlagsOffset);
        e.live_flags = live_values[i];
        e.readable = true;

        if (intact) {
            e.snapshot_flags = values[i];
            const bool snap_native = (e.snapshot_flags & kAccNative) != 0;
            const bool live_native = (e.live_flags & kAccNative) != 0;
            e.any_drift = (e.snapshot_flags != e.live_flags);
            e.native_flipped_on = !snap_native && live_native;
            e.native_flipped_off = snap_native && !live_native;
        } else {
            e.snapshot_flags = e.live_flags;
            e.any_drift = false;
        }
    }

    if (!intact) {
        for (size_t i = 0; i < n; ++i) values[i] = live_values[i];
        for (size_t i = n; i < kAccessFlagsMaxEntries; ++i) values[i] = 0;
        store_hash_for_current_values();
        RLOGW("F18 Vector F: baseline tampered — recaptured");
    }

    reprotect_pages();
    log_access_flags_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_access_flags_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
