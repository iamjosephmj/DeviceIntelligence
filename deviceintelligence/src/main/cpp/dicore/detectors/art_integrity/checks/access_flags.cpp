#include "dicore/detectors/art_integrity/checks/access_flags.h"

#include "dicore/platform/log.h"
#include "dicore/platform/svc_io.h"
#include "dicore/crypto/sha256.h"
#include "dicore/detectors/art_integrity/runtime/offsets.h"
#include "dicore/detectors/art_integrity/runtime/registry.h"

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

// Mirrors Vector E's storage. Values page holds
// `uint32_t access_flags_[kAccessFlagsMaxEntries]`, hash page
// holds the SHA-256 of those bytes.
ProtectedStore g_store;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes =
    sizeof(uint32_t) * kAccessFlagsMaxEntries;

void log_access_flags_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    std::string maps;
    if (!svc::read_file("/proc/self/maps", &maps)) return;
    char vals_perms[8] = "?";
    char hash_perms[8] = "?";
    const auto vals_addr =
        reinterpret_cast<uintptr_t>(g_store.values_page());
    const auto hash_addr =
        reinterpret_cast<uintptr_t>(g_store.hash_page());
    svc::LineCursor cur(maps);
    std::string line;
    while (cur.next(&line)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (std::sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (vals_addr >= start && vals_addr < end) {
            std::strncpy(vals_perms, perms, sizeof(vals_perms) - 1);
        }
        if (hash_addr >= start && hash_addr < end) {
            std::strncpy(hash_perms, perms, sizeof(hash_perms) - 1);
        }
    }
    RLOGI("F18 Vector F audit: values@%p perms=%s, hash@%p perms=%s "
          "(expected ---p / ---p)",
          g_store.values_page(), vals_perms,
          g_store.hash_page(), hash_perms);
}

}  // namespace

void initialize_access_flags() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    if (!g_store.init(kBaselineValuesBytes)) return;
    if (!g_store.unprotect()) return;

    auto* values = static_cast<uint32_t*>(g_store.values());
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
    g_store.rehash();

    for (size_t i = 0; i < n; ++i) {
        const FrozenMethodSpec* spec = spec_at(i);
        RLOGI("F18 Vector F snap[%zu] %-40s access_flags_=0x%08x (native=%d)",
              i, spec ? spec->short_id : "<unknown>",
              values[i], (values[i] & kAccNative) ? 1 : 0);
    }
    g_baseline_set.store(true, std::memory_order_release);
    g_store.reprotect();
    RLOGI("F18 Vector F: snapshot captured at JNI_OnLoad (%zu slots)", n);
}

size_t scan_access_flags(AccessFlagsScanEntry* out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_baseline_set.load(std::memory_order_acquire)) {
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }
    if (!g_store.init(kBaselineValuesBytes)) return 0;
    if (!g_store.unprotect()) return 0;

    auto* values = static_cast<uint32_t*>(g_store.values());
    bool intact = g_store.intact();

    const size_t reg_size = registry_size();
    const size_t n = (reg_size < out_capacity) ? reg_size : out_capacity;
    if (n > kAccessFlagsMaxEntries) {
        g_store.reprotect();
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
        g_store.rehash();
        RLOGW("F18 Vector F: baseline tampered — recaptured");
    }

    g_store.reprotect();
    log_access_flags_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_access_flags_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
