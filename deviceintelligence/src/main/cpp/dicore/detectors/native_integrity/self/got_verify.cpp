#include "dicore/detectors/native_integrity/self/got_verify.h"

#include "dicore/platform/log.h"
#include "dicore/crypto/sha256.h"
#include "dicore/detectors/native_integrity/process/range_map.h"
#include "dicore/detectors/native_integrity/self/got_sections.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "dicore/platform/protected_store.h"

namespace dicore::native_integrity {

namespace {

// 64-bit ELF section header layout. ARM64 + x86_64 are both
// 64-bit ELF; we never ship a 32-bit `.so` (build.gradle sets
// abiFilters to arm64-v8a + x86_64 only). 32-bit support would
// just need a parallel Elf32_Shdr path — defer that until/if
// 32-bit ABIs are reintroduced.
struct GotState {
    GotSection got;       // `.got`
    GotSection got_plt;   // `.got.plt` (function pointers, ELF lazy-bind)
    std::vector<uintptr_t> snapshot;       // values at OnLoad
    std::vector<Region>    snapshot_class; // classification at OnLoad
    bool initialized = false;
};

GotState g_state;
std::mutex g_mutex;
std::atomic<bool> g_initialized{false};

// PROT_NONE-page audit: if an attacker flips the snapshot pages
// to RW and rewrites our cached GOT values, the hash-of-snapshot
// fails on the next scan. Same shape as text_verify.
ProtectedStore g_store;

void initialize_locked() {
    if (g_state.initialized) return;
    const auto layout = libdicore_layout();
    if (layout.base_addr == 0) {
        RLOGW("native_integrity: G4 init: libdicore base unknown, skip");
        return;
    }
    const char* compound_path = libdicore_path();
    if (compound_path == nullptr) {
        RLOGW("native_integrity: G4 init: libdicore path unknown, skip");
        return;
    }

    GotSection got{}, got_plt{};
    if (!locate_got_sections(layout.base_addr, compound_path, &got, &got_plt)) {
        RLOGW("native_integrity: G4 init: could not locate .got sections for %s", compound_path);
        return;
    }
    g_state.got = got;
    g_state.got_plt = got_plt;

    const size_t total_slots = got.slot_count + got_plt.slot_count;
    g_state.snapshot.reserve(total_slots);
    g_state.snapshot_class.reserve(total_slots);

    auto snapshot_section = [&](const GotSection& sec) {
        if (!sec.valid) return;
        const auto* slots = reinterpret_cast<const uintptr_t*>(sec.addr_in_image);
        for (size_t i = 0; i < sec.slot_count; ++i) {
            const uintptr_t v = slots[i];
            g_state.snapshot.push_back(v);
            g_state.snapshot_class.push_back(classify(reinterpret_cast<const void*>(v)));
        }
    };
    snapshot_section(g_state.got);
    snapshot_section(g_state.got_plt);

    // Persist the snapshot in PROT_NONE storage.
    const size_t bytes = g_state.snapshot.size() * sizeof(uintptr_t);
    if (!g_store.init(bytes)) {
        // Snapshot still kept in RW vector; we lose the audit but
        // the comparison still works.
        g_state.initialized = true;
        RLOGW("native_integrity: G4 init: PROT_NONE storage unavailable, snapshot in RW");
        return;
    }
    std::memcpy(g_store.values(), g_state.snapshot.data(), bytes);
    g_store.seal();
    g_state.initialized = true;
    g_initialized.store(true, std::memory_order_release);

    RLOGI(
        "native_integrity: G4 GOT snapshot got=%zu gotplt=%zu total_slots=%zu",
        got.slot_count, got_plt.slot_count, total_slots
    );
}

}  // namespace

void initialize_got_verify() {
    std::lock_guard<std::mutex> lock(g_mutex);
    initialize_locked();
}

size_t scan_got_integrity(GotRecord* out, size_t capacity) {
    if (out == nullptr) return 0;
    if (!g_initialized.load(std::memory_order_acquire)) return SIZE_MAX;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_state.initialized) return SIZE_MAX;

    // Re-validate the PROT_NONE snapshot before trusting it.
    // We use the in-RAM g_state.snapshot for the compare; the PROT_NONE store is
    // the audit, not the source of truth. If the audit fails we disable G4 for
    // this scan to avoid false positives from a tampered baseline.
    bool baseline_intact = true;
    if (g_store.ready()) {
        if (g_store.unprotect()) {
            baseline_intact = g_store.intact();
            g_store.reprotect();
        } else {
            baseline_intact = false;
        }
    }
    if (!baseline_intact) {
        RLOGW("native_integrity: G4 baseline hash-of-hash mismatch, skip scan");
        return 0;
    }

    size_t flagged = 0;
    auto walk_section = [&](const GotSection& sec, uint32_t base_index) {
        if (!sec.valid) return;
        const auto* slots = reinterpret_cast<const uintptr_t*>(sec.addr_in_image);
        for (size_t i = 0; i < sec.slot_count; ++i) {
            if (flagged >= capacity) return;
            const uintptr_t live = slots[i];
            const uint32_t global_idx = base_index + static_cast<uint32_t>(i);
            const uintptr_t snap = g_state.snapshot[global_idx];
            const Region snap_class = g_state.snapshot_class[global_idx];
            const Region live_class = classify(reinterpret_cast<const void*>(live));
            const bool drifted = (live != snap);
            // GOT slots that the linker filled with 0 (lazy-bind
            // not yet triggered) are legitimate.
            //
            // For the out-of-range check we use is_in_known_image
            // (whole-image extent) rather than classify (RX only),
            // because GOT slots legitimately point into:
            //   - other libraries' data segments (extern globals)
            //   - libdicore's own .data / .data.rel.ro / .bss
            //     via PIC R_AARCH64_RELATIVE relocations
            // Both of those would false-positive `classify == UNKNOWN`.
            const bool out_of_range = (live != 0) &&
                !is_in_known_image(reinterpret_cast<const void*>(live));
            if (!drifted && !out_of_range) continue;
            GotRecord rec{};
            rec.slot_index = global_idx;
            rec.live_class = static_cast<uint8_t>(live_class);
            rec.snapshot_class = static_cast<uint8_t>(snap_class);
            rec.drifted = drifted;
            rec.out_of_range = out_of_range;
            rec.live_value = live;
            rec.snapshot_value = snap;
            out[flagged++] = rec;
        }
    };
    walk_section(g_state.got, 0);
    walk_section(g_state.got_plt, static_cast<uint32_t>(g_state.got.slot_count));
    return flagged;
}

}  // namespace dicore::native_integrity
