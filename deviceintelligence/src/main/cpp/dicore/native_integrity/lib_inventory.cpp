#include "lib_inventory.h"

#include "../log.h"
#include "baseline.h"
#include "range_map.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <link.h>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace dicore::native_integrity {

namespace {

std::vector<std::string> g_expected_filenames;
std::mutex g_expected_mutex;

/**
 * ART-internal anonymous-mapping label patterns. Kept as a tiny
 * fallback for the (rare) case where the JIT cache wasn't
 * present in /proc/self/maps at JNI_OnLoad time and therefore
 * isn't covered by [is_anon_label_in_baseline]. These are
 * stable Android internals across all OEMs (ART is shipped from
 * the com.android.art APEX), so they don't carry the OEM
 * maintenance burden the old `kKnownLabels` table did.
 *
 * Everything else previously in `kKnownLabels` (linker_alloc,
 * libc_malloc, scudo, dalvik-zygote-..., [stack], [heap], [vdso])
 * is reachable via the baseline snapshot — those mappings exist
 * before any user code runs and so are captured automatically.
 */
constexpr const char* kArtJitLabelPatterns[] = {
    "[anon:dalvik-jit-code-cache",
    "[anon:jit-cache",
    "[anon:jit-code-cache",
    "[anon_shmem:dalvik-jit-code-cache",
    "[anon_shmem:dalvik-zygote-jit-code-cache",
    "[anon_shmem:jit-cache",
    "[anon_shmem:jit-code-cache",
};

bool starts_with(const char* s, const char* prefix) {
    return std::strncmp(s, prefix, std::strlen(prefix)) == 0;
}

/**
 * Canonical AOSP read-only system partition prefixes — stable since
 * Android 8 (Project Treble). Anything mapped from these directories
 * was placed there by a system update through dm-verity / vbmeta and
 * cannot be modified without bootloader-unlock + filesystem remount
 * (which other detectors catch independently:
 *  - `runtime.root` flips on Magisk / SuperSU / unlocked-bootloader
 *  - `integrity.bootloader` flips when verifiedboot != Verified
 *  - `attestation.key` ships the attestation chain to the backend).
 *
 * On emulators and OEMs that lazy-load vendor GL / HAL implementations
 * after JNI_OnLoad, the OEM-self-adapt baseline rule misses these
 * libraries — they become "loaded post-baseline from a directory the
 * baseline never saw". This list is the safety net so those false
 * positives surface as `system_library_late_loaded` (MEDIUM, kept for
 * forensics) rather than `injected_library` (HIGH, panicky).
 */
constexpr const char* kSystemPathPrefixes[] = {
    "/system/",
    "/system_ext/",
    "/product/",
    "/odm/",
    "/vendor/",
    "/apex/",
    "/data/dalvik-cache/",
};

bool is_system_path_prefix(const char* path) {
    for (const char* p : kSystemPathPrefixes) {
        if (starts_with(path, p)) return true;
    }
    return false;
}

const char* basename_of(const char* path) {
    const char* slash = std::strrchr(path, '/');
    return slash ? slash + 1 : path;
}

bool is_filename_allowlisted(const char* filename) {
    std::lock_guard<std::mutex> lock(g_expected_mutex);
    for (const auto& f : g_expected_filenames) {
        if (f == filename) return true;
    }
    return false;
}

bool is_art_jit_label_fallback(const char* label, size_t label_len) {
    for (const char* kl : kArtJitLabelPatterns) {
        const size_t kl_len = std::strlen(kl);
        if (label_len < kl_len) continue;
        if (std::strncmp(label, kl, kl_len) == 0) return true;
    }
    return false;
}

bool perms_executable(const char* perms) {
    return perms[2] == 'x';
}

void scan_loaded_libs_via_dl(std::vector<InventoryRecord>& out, size_t capacity) {
    struct Ctx {
        std::vector<InventoryRecord>* out;
        size_t capacity;
    };
    Ctx ctx{&out, capacity};
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t /*sz*/, void* user) -> int {
        auto* c = reinterpret_cast<Ctx*>(user);
        if (c->out->size() >= c->capacity) return 1;
        if (!info->dlpi_name) return 0;
        const char* name = info->dlpi_name;
        if (name[0] == '\0') return 0;  // main exe — skip

        // Only flag images that have at least one PF_X PT_LOAD;
        // pure-data shared objects (rare but possible) aren't a
        // hooking risk.
        bool has_exec = false;
        for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
            const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
            if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X) != 0) {
                has_exec = true;
                break;
            }
        }
        if (!has_exec) return 0;

        // Trust derivation, in priority order:
        //   1. Loaded into the process before our JNI_OnLoad ran,
        //      OR sits in a directory that contained at least one
        //      such library, OR sits under our own app's lib dir.
        //      This is the OEM-self-adapt rule: if zygote ever
        //      preloaded any library from /foo_partition/lib64/
        //      then /foo_partition/lib64/libnewthing.so loaded
        //      later inherits trust without us hardcoding the
        //      partition name. Replaces the old `kSystemPathPrefixes`
        //      and `kKernelPseudoImageNames` allowlists.
        if (is_library_in_baseline(name)) return 0;
        // 2. Build-time inventory match by basename. Defence-in-
        //    depth: if a consumer app explicitly enumerated their
        //    own bundled `.so`s, accept them even if dlopen()
        //    happened post-baseline.
        if (is_filename_allowlisted(basename_of(name))) return 0;

        // Falls outside baseline + filename inventory. Two cases:
        //
        //  - Path is rooted in a canonical AOSP system partition
        //    (`/system/`, `/vendor/`, `/apex/`, …). Read-only,
        //    dm-verity-protected; an attacker writing here needs
        //    bootloader unlock + remount, which is itself caught
        //    by `runtime.root` + `integrity.bootloader`. Common on
        //    emulators (lazy-loaded GL stack from `/vendor/`) and
        //    OEMs that defer vendor library init. Surface as a
        //    SOFT finding so the data is preserved for forensics
        //    without producing 30+ HIGH-severity false positives.
        //
        //  - Anywhere else (`/data/local/tmp/`, `/sdcard/`,
        //    `/storage/`, `/dev/shm/`, …). That's the canonical
        //    Frida-gadget / LD_PRELOAD signal. Surface as a HARD
        //    finding (HIGH severity).
        InventoryRecord rec{};
        rec.kind = is_system_path_prefix(name)
            ? InventoryRecord::Kind::SYSTEM_LIB_LATE_LOADED
            : InventoryRecord::Kind::INJECTED_LIBRARY;
        const size_t copy_len = std::min<size_t>(std::strlen(name), sizeof(rec.path) - 1);
        std::memcpy(rec.path, name, copy_len);
        rec.path[copy_len] = '\0';
        rec.perms[0] = '\0';
        c->out->push_back(rec);
        return 0;
    }, &ctx);
}

void scan_anon_exec_via_maps(std::vector<InventoryRecord>& out, size_t capacity) {
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        if (out.size() >= capacity) break;

        unsigned long start = 0, end = 0, offset = 0;
        char perms[5] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        int consumed = 0;
        if (std::sscanf(line, "%lx-%lx %4s %lx %15s %lu %n",
                        &start, &end, perms, &offset, dev, &inode,
                        &consumed) < 6) {
            continue;
        }
        if (!perms_executable(perms)) continue;

        // Extents that were already executable at baseline time
        // are trusted regardless of how their path/label is
        // classified below — they're part of the snapshot the
        // process started with. Catches both the "JIT cache was
        // pre-existing" and the "linker pseudo-image" cases
        // without depending on label/path string matching.
        if (is_address_in_baseline_rx(static_cast<uintptr_t>(start))) continue;

        const char* p = line + consumed;
        while (*p == ' ' || *p == '\t') ++p;
        size_t path_len = std::strlen(p);
        while (path_len > 0 &&
               (p[path_len - 1] == '\n' ||
                p[path_len - 1] == ' ' ||
                p[path_len - 1] == '\t')) {
            --path_len;
        }

        // Three buckets the executable mapping can fall into:
        //  1. Truly anonymous (no path, no label) → always flag
        //  2. Bracketed label like [anon:...] → trust iff
        //     baseline saw the same label (JIT cache grew) or
        //     it matches the small ART JIT fallback list
        //  3. File-backed → trust iff baseline trusts the path
        //     (directory inheritance) or it's our own bundled lib
        if (path_len == 0) {
            // Truly anonymous executable mapping that wasn't in
            // baseline. Always flag.
        } else if (p[0] == '[') {
            // Bracketed label (kernel-managed anon).
            if (is_anon_label_in_baseline(p, path_len)) continue;
            if (is_art_jit_label_fallback(p, path_len)) continue;
        } else {
            // File-backed (or memfd).
            char path_buf[1024];
            const size_t copy_len = std::min<size_t>(path_len, sizeof(path_buf) - 1);
            std::memcpy(path_buf, p, copy_len);
            path_buf[copy_len] = '\0';

            // Memfd-backed JIT: `/memfd:jit-cache (deleted)` etc.
            // ART ships its JIT cache as a sealed memfd on newer
            // Android builds; baseline captures the original
            // memfd extent but the cache may grow into new memfd
            // mappings during process lifetime. Mirror the
            // ranges.cpp decision and trust any memfd whose name
            // contains "jit" / "art" / "zygote".
            if (starts_with(path_buf, "/memfd:")) {
                if (std::strstr(path_buf, "jit") != nullptr) continue;
                if (std::strstr(path_buf, "art") != nullptr) continue;
                if (std::strstr(path_buf, "zygote") != nullptr) continue;
            }
            // Path-trust via baseline: if any baseline RX mapping
            // lived in the same directory, trust this one too.
            // Catches every system partition (`/system/`,
            // `/system_ext/`, `/product/`, `/odm/`, `/vendor/`,
            // `/apex/`, `/data/dalvik-cache/`, OEM-specific
            // partitions we've never heard of) without ever
            // hardcoding their names.
            if (is_library_in_baseline(path_buf)) continue;
            // Build-time inventory match.
            if (is_filename_allowlisted(basename_of(path_buf))) continue;
            // Canonical AOSP system path → already represented by
            // the dl-iterate-phdr scanner as a SYSTEM_LIB_LATE_LOADED
            // record (one finding per library, not one per PT_LOAD
            // segment). Skip here to avoid the double-count we saw
            // on emulators where every late-loaded `/vendor/lib64/`
            // GL library produced both an `injected_library` and
            // an `injected_anonymous_executable` finding for the
            // same `.so`.
            if (is_system_path_prefix(path_buf)) continue;

            // Anything else → flag, with the file path as `path`.
            InventoryRecord rec{};
            rec.kind = InventoryRecord::Kind::INJECTED_ANON_EXEC;
            const size_t pcopy = std::min<size_t>(std::strlen(path_buf), sizeof(rec.path) - 1);
            std::memcpy(rec.path, path_buf, pcopy);
            rec.path[pcopy] = '\0';
            std::memcpy(rec.perms, perms, 5);
            rec.perms[4] = '\0';
            out.push_back(rec);
            continue;
        }

        // Reach here only for truly anonymous OR unknown bracketed
        // executable mappings. Format the path field as
        // "anon:<start>-<end>" (or "anon:<label>@<start>") for
        // forensic value.
        InventoryRecord rec{};
        rec.kind = InventoryRecord::Kind::INJECTED_ANON_EXEC;
        if (path_len == 0) {
            std::snprintf(rec.path, sizeof(rec.path), "anon:0x%lx-0x%lx",
                          static_cast<unsigned long>(start),
                          static_cast<unsigned long>(end));
        } else {
            std::snprintf(rec.path, sizeof(rec.path), "anon:%.*s@0x%lx",
                          static_cast<int>(std::min<size_t>(path_len, 256)),
                          p,
                          static_cast<unsigned long>(start));
        }
        std::memcpy(rec.perms, perms, 5);
        rec.perms[4] = '\0';
        out.push_back(rec);
    }
    std::fclose(f);
}

}  // namespace

void set_expected_so_inventory(const char* const* filenames, size_t count) {
    std::lock_guard<std::mutex> lock(g_expected_mutex);
    g_expected_filenames.clear();
    g_expected_filenames.reserve(count + 1);
    for (size_t i = 0; i < count; ++i) {
        if (filenames[i] == nullptr) continue;
        g_expected_filenames.emplace_back(filenames[i]);
    }
    // libdicore.so is always implicitly allowlisted: it's our own
    // image. The build-time inventory should include it but if a
    // build pipeline ever drops it, we still don't want to flag
    // ourselves.
    bool has_self = false;
    for (const auto& f : g_expected_filenames) {
        if (f == "libdicore.so") { has_self = true; break; }
    }
    if (!has_self) g_expected_filenames.emplace_back("libdicore.so");
    RLOGI("native_integrity: G3 expected so inventory installed (%zu entries)",
          g_expected_filenames.size());
}

size_t scan_loaded_libraries(InventoryRecord* out, size_t capacity) {
    if (out == nullptr || capacity == 0) return 0;
    std::vector<InventoryRecord> collected;
    collected.reserve(8);
    scan_loaded_libs_via_dl(collected, capacity);
    if (collected.size() < capacity) {
        scan_anon_exec_via_maps(collected, capacity);
    }
    const size_t n = std::min(collected.size(), capacity);
    for (size_t i = 0; i < n; ++i) {
        out[i] = collected[i];
    }
    return n;
}

}  // namespace dicore::native_integrity
