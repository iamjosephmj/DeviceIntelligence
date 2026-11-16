#include "dicore/detectors/art_integrity/runtime/snapshot.h"

#include "dicore/platform/log.h"
#include "dicore/platform/svc_io.h"
#include "dicore/crypto/sha256.h"
#include "dicore/detectors/art_integrity/runtime/offsets.h"
#include "dicore/detectors/art_integrity/runtime/ranges.h"
#include "dicore/detectors/art_integrity/runtime/registry.h"

#include <android/api-level.h>
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

// Cached entry-point offset for the running Android API. Resolved
// once on first scan; the value can't change for the process
// lifetime so we don't need a mutex.
size_t cached_entry_offset() {
    static const size_t kOffset =
        entry_point_offset(android_get_device_api_level());
    return kOffset;
}

// Self-protected baseline storage. Two separate `mmap`-backed
// pages, kept at PROT_NONE between scans. Allocating each
// independently lets the kernel place them at random addresses
// (full ASLR), so an attacker scanning process memory for a
// known method-pointer signature can't trivially locate the
// hash page once they've found the value page (or vice versa).
//
// Layout:
//   - g_baseline_values_page: holds the array of live entry
//     pointers indexed by registry slot. Sized to one OS page
//     (the values themselves only occupy ~80 bytes; the rest is
//     deliberate padding so the layout doesn't betray the data).
//   - g_baseline_hash_page: holds a 32-byte SHA-256 of the
//     values, mapped separately.
//
// On compare we PROT_READ both pages, recompute the SHA-256 of
// the values, verify it matches the stored hash, then PROT_NONE
// both. A mismatch => an attacker tampered with the baseline
// between scans, which is itself a finding.
ProtectedStore g_store;
std::atomic<bool> g_baseline_set{false};
std::mutex g_baseline_mutex;
std::atomic<bool> g_last_scan_intact{true};

constexpr size_t kBaselineValuesBytes = sizeof(const void*) * kMaxScanEntries;

// One-shot self-verification: after the first baseline capture
// re-reads /proc/self/maps and confirms our two pages are
// listed with `---p` (PROT_NONE) perms. Runs once per process
// so we don't burn cycles on every scan; the log line is the
// M6 CTF evidence.
void log_baseline_protection_audit() {
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
        if (start == values_addr) std::strncpy(values_perms, perms, sizeof(values_perms) - 1);
        if (start == hash_addr) std::strncpy(hash_perms, perms, sizeof(hash_perms) - 1);
    }
    RLOGI("F18 baseline audit: values@%p perms=%s, hash@%p perms=%s (expected ---p / ---p)",
          g_store.values_page(), values_perms, g_store.hash_page(), hash_perms);
}

}  // namespace

size_t scan_live(ScanEntry* out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;
    const size_t offset = cached_entry_offset();
    if (offset == kUnknownOffset) {
        // Below our floor or unknown table entry — bail out so
        // callers don't dereference garbage. They'll see zero
        // entries and degrade.
        return 0;
    }
    const size_t reg_size = registry_size();
    const size_t n = (reg_size < out_capacity) ? reg_size : out_capacity;

    // Serialise scans so the protect/unprotect dance is atomic
    // with respect to the baseline pages. The lock also guards
    // the first-scan baseline-capture race.
    std::lock_guard<std::mutex> lock(g_baseline_mutex);
    const bool baseline_was_set = g_baseline_set.load(std::memory_order_acquire);
    if (!g_store.init(kBaselineValuesBytes)) {
        // mmap failed — extremely unlikely. Degrade to "no baseline".
        g_last_scan_intact.store(true, std::memory_order_release);
        return 0;
    }

    bool intact = true;
    bool unprotected = g_store.unprotect();
    if (!unprotected) {
        // Protection toggle failed. Treat as intact (don't false-
        // positive) and skip diff.
        g_last_scan_intact.store(true, std::memory_order_release);
        return 0;
    }

    auto* baseline_values = static_cast<const void**>(g_store.values());

    if (baseline_was_set) {
        intact = g_store.intact();
    }

    void* live_values[kMaxScanEntries] = {};
    for (size_t i = 0; i < n; ++i) {
        ScanEntry& e = out[i];
        e.short_id = nullptr;
        e.snapshot_entry = nullptr;
        e.live_entry = nullptr;
        e.snapshot_class = Classification::UNKNOWN;
        e.live_class = Classification::UNKNOWN;
        e.readable = false;
        e.drifted = false;

        const ResolvedMethod* slot = resolved_at(i);
        if (slot == nullptr) {
            const FrozenMethodSpec* spec = spec_at(i);
            e.short_id = spec ? spec->short_id : "<unknown>";
            continue;
        }
        e.short_id = slot->spec->short_id;
        if (!slot->entry_point_readable) {
            continue;
        }
        live_values[i] = read_entry_point(slot->method_id, offset);
        e.live_entry = live_values[i];
        e.live_class = e.live_entry != nullptr
            ? classify(e.live_entry)
            : Classification::UNKNOWN;
        e.readable = true;
        if (baseline_was_set && intact) {
            e.snapshot_entry = baseline_values[i];
            e.snapshot_class = e.snapshot_entry != nullptr
                ? classify(e.snapshot_entry)
                : Classification::UNKNOWN;
            e.drifted = (e.live_entry != e.snapshot_entry);
        } else {
            // Either first scan, or baseline tampered (we
            // recapture in the latter case so the next scan has a
            // fresh, intact baseline). Report no drift this round.
            e.snapshot_entry = e.live_entry;
            e.snapshot_class = e.live_class;
            e.drifted = false;
        }
    }

    if (!baseline_was_set || !intact) {
        for (size_t i = 0; i < n; ++i) {
            baseline_values[i] = live_values[i];
        }
        // Zero out any remainder of the page so the layout doesn't
        // depend on which slots happened to be readable.
        for (size_t i = n; i < kMaxScanEntries; ++i) {
            baseline_values[i] = nullptr;
        }
        g_store.rehash();
        g_baseline_set.store(true, std::memory_order_release);
        if (!baseline_was_set) {
            RLOGI("F18 baseline: captured %zu entry pointers (mmap-protected)", n);
        } else {
            RLOGW("F18 baseline: tampered — recaptured");
        }
    }

    g_store.reprotect();
    log_baseline_protection_audit();
    g_last_scan_intact.store(intact || !baseline_was_set,
                              std::memory_order_release);
    return n;
}

bool last_scan_baseline_intact() {
    return g_last_scan_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
