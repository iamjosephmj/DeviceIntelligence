#include "baseline.h"

#include "../log.h"
#include "range_map.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <link.h>
#include <mutex>
#include <string>
#include <vector>

namespace dicore::native_integrity {

namespace {

struct Range {
    uintptr_t start;
    uintptr_t end;  // exclusive
};

// All static state. Populated once by initialize_baseline() and
// then read-only for the rest of the process's lifetime; no
// synchronization needed on the read paths.
std::vector<std::string> g_baseline_lib_paths;
std::vector<std::string> g_baseline_lib_dirs;     // unique parent dirs of g_baseline_lib_paths
std::vector<Range>       g_baseline_rx_extents;   // every RX mapping (file-backed + labeled anon)
std::vector<std::string> g_baseline_anon_labels;  // unique [anon:...] / [anon_shmem:...] labels
std::vector<std::string> g_baseline_file_dirs;    // unique parent dirs of file-backed RX maps
std::string              g_our_app_lib_dir;       // e.g. "/data/app/.../base.apk!/lib/arm64-v8a"

std::once_flag g_once;

// Mutable list of directories declared trusted at runtime by
// the Kotlin layer (typically the app's own data dir). Read on
// every G3 scan; written from the first DeviceIntelligence
// init. Guarded by g_runtime_mutex to allow safe concurrent
// reads + occasional appends.
std::vector<std::string> g_runtime_trusted_dirs;
std::mutex               g_runtime_mutex;

// Serialises concurrent G7 cache misses through the
// /proc/self/maps reparse path so we don't have N threads each
// opening /proc/self/maps simultaneously.
std::mutex g_refresh_mutex;

// ---- helpers ---------------------------------------------------------------

bool addr_in(const std::vector<Range>& v, uintptr_t a) {
    for (const auto& r : v) {
        if (a >= r.start && a < r.end) return true;
    }
    return false;
}

void push_unique(std::vector<std::string>& v, std::string s) {
    if (s.empty()) return;
    for (const auto& existing : v) {
        if (existing == s) return;
    }
    v.push_back(std::move(s));
}

std::string dirname_of(const char* path) {
    if (path == nullptr || path[0] == '\0') return {};
    const char* slash = std::strrchr(path, '/');
    if (slash == nullptr || slash == path) return {};
    return std::string(path, slash - path);
}

// Strips the basename off an APK-embedded library path so we
// trust everything from the same lib directory (different ABIs
// of the same APK live in /lib/<other_abi>/, which is fine to
// trust as a sibling).
//
// e.g. "/data/app/.../base.apk!/lib/arm64-v8a/libdicore.so" →
//      "/data/app/.../base.apk!/lib/arm64-v8a"
std::string lib_dir_from_compound_path(const char* path) {
    return dirname_of(path);
}

// ---- baseline capture ------------------------------------------------------

int dl_callback(struct dl_phdr_info* info, size_t /*sz*/, void* user) {
    auto* lib_paths = static_cast<std::vector<std::string>*>(user);
    if (info == nullptr || info->dlpi_name == nullptr) return 0;
    const char* name = info->dlpi_name;
    if (name[0] == '\0') return 0;     // main exe — skip
    lib_paths->emplace_back(name);
    return 0;
}

// Parse /proc/self/maps and append every executable mapping's
// (start, end, label-or-path) into the supplied collectors.
//
// We intentionally accept ANY perms with 'x' in slot [2] — RX,
// RWX, R-XS, RWXS — at baseline time so a later "RWX appeared!"
// signal is judged against the broadest possible safe-state
// snapshot.
void parse_proc_maps(
    std::vector<Range>& rx_extents,
    std::vector<std::string>& anon_labels,
    std::vector<std::string>& file_dirs
) {
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (f == nullptr) return;

    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, off = 0;
        char perms[8] = {};
        char dev[16] = {};
        unsigned long inode = 0;
        int consumed = 0;
        if (std::sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                        &start, &end, perms, &off, dev, &inode,
                        &consumed) < 6) {
            continue;
        }
        if (perms[2] != 'x') continue;
        if (start >= end) continue;

        // Trim trailing whitespace / newline off the path field.
        const char* p = line + consumed;
        while (*p == ' ' || *p == '\t') ++p;
        size_t plen = std::strlen(p);
        while (plen > 0 &&
               (p[plen - 1] == '\n' || p[plen - 1] == ' ' || p[plen - 1] == '\t')) {
            --plen;
        }

        // Always record the extent — every executable mapping
        // present at baseline is part of the trust boundary,
        // regardless of how its source is classified below.
        rx_extents.push_back({static_cast<uintptr_t>(start),
                              static_cast<uintptr_t>(end)});

        if (plen == 0) {
            // Truly anonymous executable mapping at baseline. We
            // record the extent (above) but no label / dir to
            // inherit from.
            continue;
        }

        std::string path(p, plen);
        if (path[0] == '[') {
            // Bracketed kernel label (`[anon:...]`,
            // `[anon_shmem:...]`, `[vdso]`, etc). Track for
            // label-inheritance.
            push_unique(anon_labels, std::move(path));
        } else {
            // File-backed mapping. Track its parent directory
            // so future mappings from the same dir inherit
            // trust without us hardcoding the partition name.
            std::string dir = dirname_of(path.c_str());
            push_unique(file_dirs, std::move(dir));
        }
    }
    std::fclose(f);
}

void initialize_baseline_locked() {
    // 1. Library paths via dl_iterate_phdr.
    dl_iterate_phdr(&dl_callback, &g_baseline_lib_paths);

    // 2. Derive unique parent directories of those library paths
    //    so future loads from the same dir inherit trust.
    for (const auto& p : g_baseline_lib_paths) {
        std::string d = dirname_of(p.c_str());
        push_unique(g_baseline_lib_dirs, std::move(d));
    }

    // 3. Walk /proc/self/maps for every executable mapping.
    parse_proc_maps(g_baseline_rx_extents, g_baseline_anon_labels, g_baseline_file_dirs);

    // 4. Our own app's lib directory, derived from libdicore's
    //    loader-reported path. Used by G3 to trust legitimate
    //    lazy-loaded `.so`s bundled in our own APK (same dir as
    //    libdicore) without taking the "loaded after baseline"
    //    path that flags injected libraries.
    if (const char* our_path = libdicore_path()) {
        g_our_app_lib_dir = lib_dir_from_compound_path(our_path);
    }

    RLOGI(
        "native_integrity: G3/G7 baseline captured libs=%zu lib_dirs=%zu "
        "rx_extents=%zu anon_labels=%zu file_dirs=%zu app_lib_dir=%s",
        g_baseline_lib_paths.size(),
        g_baseline_lib_dirs.size(),
        g_baseline_rx_extents.size(),
        g_baseline_anon_labels.size(),
        g_baseline_file_dirs.size(),
        g_our_app_lib_dir.empty() ? "(unknown)" : g_our_app_lib_dir.c_str()
    );
}

bool dir_in(const std::vector<std::string>& dirs, const char* path) {
    if (path == nullptr || path[0] == '\0') return false;
    for (const auto& d : dirs) {
        if (d.empty()) continue;
        // Match path under d if path starts with d + '/'.
        const size_t dl = d.size();
        if (std::strncmp(path, d.c_str(), dl) != 0) continue;
        if (path[dl] == '/') return true;
        if (path[dl] == '\0') return true;
    }
    return false;
}

}  // namespace

size_t initialize_baseline() {
    std::call_once(g_once, &initialize_baseline_locked);
    return g_baseline_lib_paths.size() + g_baseline_rx_extents.size();
}

bool is_library_in_baseline(const char* path) {
    if (path == nullptr || path[0] == '\0') return false;
    initialize_baseline();

    // Exact match against any library captured at baseline.
    for (const auto& bp : g_baseline_lib_paths) {
        if (bp == path) return true;
    }
    // Directory-inheritance: trust any path under a directory
    // that contained at least one baseline-loaded library. This
    // is the OEM-self-adapt rule.
    if (dir_in(g_baseline_lib_dirs, path)) return true;

    // Our own APK's lib directory: legitimate lazy-loaded `.so`s
    // bundled with the consumer app live next to libdicore.
    if (!g_our_app_lib_dir.empty()) {
        const size_t dl = g_our_app_lib_dir.size();
        if (std::strncmp(path, g_our_app_lib_dir.c_str(), dl) == 0 &&
            (path[dl] == '/' || path[dl] == '\0')) {
            return true;
        }
    }

    // Runtime-declared trusted directories (e.g. the consumer
    // app's own dataDir). Snapshot under the lock then dir-in
    // check on the snapshot to avoid holding the lock during
    // the scan.
    std::vector<std::string> snapshot;
    {
        std::lock_guard<std::mutex> lk(g_runtime_mutex);
        snapshot = g_runtime_trusted_dirs;
    }
    if (dir_in(snapshot, path)) return true;
    return false;
}

void add_trusted_directory(const char* path) {
    if (path == nullptr || path[0] == '\0') return;
    // Normalise: strip trailing '/' so dir_in's
    // "starts_with(path, dir + '/')" matches consistently.
    std::string p(path);
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    if (p.empty()) return;

    std::lock_guard<std::mutex> lk(g_runtime_mutex);
    for (const auto& existing : g_runtime_trusted_dirs) {
        if (existing == p) return;
    }
    g_runtime_trusted_dirs.push_back(p);
    RLOGI("native_integrity: trusted directory added path=%s (total runtime=%zu)",
          p.c_str(), g_runtime_trusted_dirs.size());
}

bool is_address_in_baseline_rx(uintptr_t addr) {
    initialize_baseline();
    return addr_in(g_baseline_rx_extents, addr);
}

bool is_anon_label_in_baseline(const char* label, size_t label_len) {
    if (label == nullptr || label_len == 0) return false;
    initialize_baseline();
    for (const auto& bl : g_baseline_anon_labels) {
        if (bl.size() != label_len) continue;
        if (std::memcmp(bl.data(), label, label_len) == 0) return true;
    }
    return false;
}

namespace {

// Re-parse /proc/self/maps and check whether `addr` falls inside
// any current executable mapping that's trusted via baseline
// inheritance:
//   - File-backed mapping whose parent directory was in baseline.
//   - Anonymous mapping whose label was in baseline.
//
// This is the "JIT cache grew" path: the new RX page wasn't in
// baseline (it was just allocated by ART's compiler), but its
// label `[anon:dalvik-jit-code-cache]` matches one we saw at
// baseline. Same logic for OAT files recompiled into a new
// extent inside an already-trusted directory.
bool address_in_grown_locked(uintptr_t addr) {
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (f == nullptr) return false;
    bool trusted = false;
    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, off = 0;
        char perms[8] = {};
        char dev[16] = {};
        unsigned long inode = 0;
        int consumed = 0;
        if (std::sscanf(line, "%lx-%lx %7s %lx %15s %lu %n",
                        &start, &end, perms, &off, dev, &inode,
                        &consumed) < 6) {
            continue;
        }
        if (perms[2] != 'x') continue;
        if (addr < start || addr >= end) continue;

        // We're on the right line. Decide if it's trusted.
        const char* p = line + consumed;
        while (*p == ' ' || *p == '\t') ++p;
        size_t plen = std::strlen(p);
        while (plen > 0 &&
               (p[plen - 1] == '\n' || p[plen - 1] == ' ' || p[plen - 1] == '\t')) {
            --plen;
        }
        if (plen == 0) {
            // Truly anonymous, post-baseline. Untrusted.
            trusted = false;
        } else if (p[0] == '[') {
            trusted = is_anon_label_in_baseline(p, plen);
        } else {
            // File-backed; check directory inheritance.
            std::string path(p, plen);
            std::string dir = dirname_of(path.c_str());
            for (const auto& bd : g_baseline_file_dirs) {
                if (bd == dir) { trusted = true; break; }
            }
            // Also accept under any baseline lib_dir (covers
            // libraries that were loaded via dl_iterate_phdr and
            // therefore appear in g_baseline_lib_dirs but didn't
            // necessarily get their own /proc/self/maps walk
            // entry into g_baseline_file_dirs because of how the
            // two snapshots interleave).
            if (!trusted) {
                for (const auto& bd : g_baseline_lib_dirs) {
                    if (bd == dir) { trusted = true; break; }
                }
            }
        }
        break;
    }
    std::fclose(f);
    return trusted;
}

}  // namespace

bool is_address_trusted_via_baseline(uintptr_t addr) {
    initialize_baseline();
    if (addr_in(g_baseline_rx_extents, addr)) return true;
    // Cache miss: refresh-on-miss against current maps. Cheap
    // (microseconds) and bounds the per-violation cost.
    std::lock_guard<std::mutex> lk(g_refresh_mutex);
    return address_in_grown_locked(addr);
}

}  // namespace dicore::native_integrity
