#include "ranges.h"

#include "../log.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <link.h>
#include <mutex>
#include <vector>

namespace dicore::art_integrity {

namespace {

struct Range {
    uintptr_t start;
    uintptr_t end;  // exclusive
};

struct RangeSet {
    std::vector<Range> libart;
    std::vector<Range> boot_oat;
    std::vector<Range> jit_cache;
    std::vector<Range> oat_other;
};

RangeSet g_ranges;
std::once_flag g_once;

bool addr_in(const std::vector<Range>& set, uintptr_t addr) {
    // Linear scan is fine — we expect <10 entries per category;
    // sorting + bsearch would buy us nothing.
    for (const auto& r : set) {
        if (addr >= r.start && addr < r.end) return true;
    }
    return false;
}

int dl_callback(struct dl_phdr_info* info, size_t /*size*/, void* user) {
    auto* set = reinterpret_cast<RangeSet*>(user);
    if (!info->dlpi_name) return 0;

    // Match libart.so by suffix. The fully-qualified path varies:
    // typically `/apex/com.android.art/lib64/libart.so` on modern
    // Android, but the suffix is stable.
    const char* name = info->dlpi_name;
    const size_t name_len = std::strlen(name);
    constexpr const char kSuffix[] = "libart.so";
    constexpr size_t kSuffixLen = sizeof(kSuffix) - 1;
    if (name_len < kSuffixLen ||
        std::strcmp(name + name_len - kSuffixLen, kSuffix) != 0) {
        return 0;
    }

    const uintptr_t base = info->dlpi_addr;
    for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD) continue;
        if ((phdr.p_flags & PF_X) == 0) continue;
        const uintptr_t start = base + phdr.p_vaddr;
        const uintptr_t end = start + phdr.p_memsz;
        set->libart.push_back({start, end});
        RLOGI("F18 ranges: libart RX [0x%lx, 0x%lx) from %s",
              static_cast<unsigned long>(start),
              static_cast<unsigned long>(end),
              name);
    }
    // We've captured this libart instance; keep iterating in case
    // there's a second one (rare but possible with linker
    // namespaces).
    return 0;
}

bool perms_executable(const char* perms) {
    // perms is exactly 4 chars: "rwxp" / "r-xp" / etc.
    return perms[2] == 'x';
}

bool path_is_boot_oat(const char* path, size_t path_len) {
    if (path_len < 5) return false;
    // Match `boot*.oat` / `boot*.art` under the conventional dirs.
    // Two-step: first endswith .oat or .art, then check the
    // basename starts with "boot".
    bool ends_oat = (std::strncmp(path + path_len - 4, ".oat", 4) == 0);
    bool ends_art = (std::strncmp(path + path_len - 4, ".art", 4) == 0);
    if (!ends_oat && !ends_art) return false;
    const char* basename = std::strrchr(path, '/');
    if (!basename) basename = path; else ++basename;
    return std::strncmp(basename, "boot", 4) == 0;
}

bool path_is_oat(const char* path, size_t path_len) {
    if (path_len < 5) return false;
    return std::strncmp(path + path_len - 4, ".oat", 4) == 0 ||
           std::strncmp(path + path_len - 4, ".art", 4) == 0 ||
           std::strncmp(path + path_len - 4, ".odex", 4) == 0;
}

bool label_is_jit_cache(const char* label) {
    // Match either of the two JIT-cache shapes we've seen across
    // Android 9 -> 16:
    //
    //   - `[anon:jit-code-cache]` / `[anon:dalvik-jit-code-cache]`
    //     on older builds where the JIT code cache is a private
    //     anonymous RWX mapping.
    //   - `/memfd:jit-cache (deleted)` /
    //     `/memfd:jit-zygote-cache (deleted)` on modern ART where
    //     the cache is memfd-backed and presents with `r-xs` perms
    //     (executable, shared, file-backed but anonymous-by-fd).
    //
    // Both are the JIT code region. We match by looking for the
    // literal substring "jit" — narrow enough to avoid colliding
    // with normal libraries, broad enough to survive future
    // kernel-label renames.
    for (const char* p = label; *p; ++p) {
        char a = *p;
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
        if (a != 'j') continue;
        char b = p[1];
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + ('a' - 'A'));
        char c = p[2];
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        if (b == 'i' && c == 't') return true;
    }
    return false;
}

void parse_proc_self_maps(RangeSet* set) {
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) {
        RLOGW("F18 ranges: failed to open /proc/self/maps");
        return;
    }
    char line[4096];
    while (std::fgets(line, sizeof(line), f)) {
        // Maps format (fields separated by whitespace, padded with
        // spaces between inode and pathname):
        //   <start>-<end> <perms> <offset> <dev> <inode>   <pathname>
        //
        // We need the address range, perms, and pathname. Use
        // sscanf with %n to find the byte offset where parsing
        // stopped, then capture the trailing pathname directly
        // (it can contain spaces / parentheses, e.g. "(deleted)").
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

        // Pathname (or anonymous label) starts at `consumed`. May
        // be empty (anon mappings). Trim leading spaces + trailing
        // newline + trailing space.
        const char* p = line + consumed;
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p || *p == '\n') continue;

        size_t path_len = std::strlen(p);
        while (path_len > 0 && (p[path_len - 1] == '\n' ||
                                p[path_len - 1] == ' ' ||
                                p[path_len - 1] == '\t')) {
            --path_len;
        }
        if (path_len == 0) continue;

        char path_buf[1024];
        if (path_len >= sizeof(path_buf)) path_len = sizeof(path_buf) - 1;
        std::memcpy(path_buf, p, path_len);
        path_buf[path_len] = '\0';

        const Range r{static_cast<uintptr_t>(start), static_cast<uintptr_t>(end)};
        if (path_buf[0] == '[') {
            if (label_is_jit_cache(path_buf)) {
                set->jit_cache.push_back(r);
                RLOGI("F18 ranges: JIT [0x%lx, 0x%lx) %s", start, end, path_buf);
            }
        } else if (label_is_jit_cache(path_buf)) {
            // Recent ART JIT-caches are memfd-backed and present as
            // `/memfd:jit-cache (deleted)` (with `r-xs` perms) in
            // maps — they're "files" by name but functionally JIT
            // cache. Catch them here so they classify correctly.
            set->jit_cache.push_back(r);
            RLOGI("F18 ranges: JIT [0x%lx, 0x%lx) %s", start, end, path_buf);
        } else if (path_is_boot_oat(path_buf, path_len)) {
            set->boot_oat.push_back(r);
            RLOGI("F18 ranges: bootOAT [0x%lx, 0x%lx) %s", start, end, path_buf);
        } else if (path_is_oat(path_buf, path_len)) {
            set->oat_other.push_back(r);
            RLOGI("F18 ranges: oat [0x%lx, 0x%lx) %s", start, end, path_buf);
        }
    }
    std::fclose(f);
}

void initialize_locked() {
    dl_iterate_phdr(&dl_callback, &g_ranges);
    parse_proc_self_maps(&g_ranges);
    RLOGI("F18 ranges: libart=%zu bootOAT=%zu jit=%zu otherOAT=%zu",
          g_ranges.libart.size(),
          g_ranges.boot_oat.size(),
          g_ranges.jit_cache.size(),
          g_ranges.oat_other.size());
}

}  // namespace

const char* classification_name(Classification c) {
    switch (c) {
        case Classification::IN_LIBART:    return "libart";
        case Classification::IN_BOOT_OAT:  return "boot_oat";
        case Classification::IN_JIT_CACHE: return "jit_cache";
        case Classification::IN_OAT_OTHER: return "oat_other";
        case Classification::UNKNOWN:      return "unknown";
    }
    return "unknown";
}

size_t initialize_ranges() {
    std::call_once(g_once, &initialize_locked);
    return g_ranges.libart.size() + g_ranges.boot_oat.size() +
           g_ranges.jit_cache.size() + g_ranges.oat_other.size();
}

Classification classify(const void* addr) {
    initialize_ranges();
    const auto a = reinterpret_cast<uintptr_t>(addr);
    if (addr_in(g_ranges.libart, a))    return Classification::IN_LIBART;
    if (addr_in(g_ranges.boot_oat, a))  return Classification::IN_BOOT_OAT;
    if (addr_in(g_ranges.jit_cache, a)) return Classification::IN_JIT_CACHE;
    if (addr_in(g_ranges.oat_other, a)) return Classification::IN_OAT_OTHER;
    return Classification::UNKNOWN;
}

size_t libart_range_count() {
    initialize_ranges();
    return g_ranges.libart.size();
}

size_t boot_oat_range_count() {
    initialize_ranges();
    return g_ranges.boot_oat.size();
}

size_t jit_cache_range_count() {
    initialize_ranges();
    return g_ranges.jit_cache.size();
}

size_t other_oat_range_count() {
    initialize_ranges();
    return g_ranges.oat_other.size();
}

}  // namespace dicore::art_integrity
