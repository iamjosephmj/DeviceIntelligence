#include "range_map.h"

#include "../log.h"
#include "baseline.h"

#include <algorithm>
#include <atomic>
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

struct RangeSet {
    std::vector<Range> libc;
    std::vector<Range> libm;
    std::vector<Range> libdl;
    std::vector<Range> libart;
    std::vector<Range> libdicore;
    std::vector<Range> other_system;
};

RangeSet g_ranges;
// Whole-image extents (any PT_LOAD: RX, RO, or RW) for every
// image we iterated. Used by [is_in_known_image] to validate G4
// GOT pointer values, which legitimately point into data segments
// of libraries (extern globals, libdicore's own RELATIVE
// relocations, etc).
std::vector<Range> g_image_extents;
LibdicoreLayout g_libdicore{0, 0, 0};
char g_libdicore_path[1024] = {};
std::once_flag g_once;

bool addr_in(const std::vector<Range>& v, uintptr_t a) {
    // Linear scan: each bucket holds <10 entries on every device
    // we've measured, so a sorted-bsearch buys nothing.
    for (const auto& r : v) {
        if (a >= r.start && a < r.end) return true;
    }
    return false;
}

bool name_endswith(const char* name, size_t name_len, const char* suffix) {
    const size_t suffix_len = std::strlen(suffix);
    if (name_len < suffix_len) return false;
    return std::strcmp(name + name_len - suffix_len, suffix) == 0;
}

bool path_starts_with(const char* path, const char* prefix) {
    return std::strncmp(path, prefix, std::strlen(prefix)) == 0;
}

int dl_callback(struct dl_phdr_info* info, size_t /*size*/, void* user) {
    auto* set = reinterpret_cast<RangeSet*>(user);
    if (!info->dlpi_name) return 0;
    const char* name = info->dlpi_name;
    const size_t name_len = std::strlen(name);
    if (name_len == 0) return 0;

    // Walk this image's PT_LOAD headers twice:
    //  1) Collect every executable (PF_X) segment as a Range for
    //     the per-library RX bucket — this is what classify() and
    //     G7 consult.
    //  2) Collect the full extent of the image (smallest p_vaddr
    //     to largest p_vaddr+p_memsz across ALL PT_LOADs) into
    //     g_image_extents for is_in_known_image() / G4.
    // The same image can have multiple RX segments on devices
    // with strict 16 KB page alignment.
    std::vector<Range> rx_ranges;
    rx_ranges.reserve(2);
    uintptr_t image_start = 0;
    uintptr_t image_end = 0;
    bool image_seen = false;
    for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD) continue;
        const uintptr_t start = info->dlpi_addr + phdr.p_vaddr;
        const uintptr_t end = start + phdr.p_memsz;
        if ((phdr.p_flags & PF_X) != 0) {
            rx_ranges.push_back({start, end});
        }
        if (!image_seen) {
            image_start = start;
            image_end = end;
            image_seen = true;
        } else {
            if (start < image_start) image_start = start;
            if (end   > image_end)   image_end   = end;
        }
    }
    if (rx_ranges.empty()) return 0;
    // Track the image's full extent — used by G4 to validate that
    // GOT pointer values resolve to *some* known image, even into
    // its data segments.
    if (image_seen && image_end > image_start) {
        g_image_extents.push_back({image_start, image_end});
    }

    // Bucket the image. Suffix matching survives the variation in
    // mounted paths (`/apex/com.android.runtime/lib64/bionic/libc.so`,
    // `/system/lib64/libc.so`, etc).
    std::vector<Range>* dest = nullptr;
    if (name_endswith(name, name_len, "libdicore.so")) {
        dest = &set->libdicore;
        // Capture libdicore's load address + first RX range as the
        // anchor for `text_verify` / `got_verify`. The base address
        // is the loader-reported `dlpi_addr` (may be 0 for the main
        // executable, never for a dlopen'd library).
        if (g_libdicore.base_addr == 0) {
            g_libdicore.base_addr = info->dlpi_addr;
            g_libdicore.rx_start = rx_ranges.front().start;
            g_libdicore.rx_end = rx_ranges.front().end;
            // Also save the on-disk path so G4 can mmap the file
            // and read section headers (which are typically not in
            // any PT_LOAD segment, hence not in memory).
            const size_t copy_len = std::min<size_t>(name_len, sizeof(g_libdicore_path) - 1);
            std::memcpy(g_libdicore_path, name, copy_len);
            g_libdicore_path[copy_len] = '\0';
        }
    } else if (name_endswith(name, name_len, "libc.so")) {
        dest = &set->libc;
    } else if (name_endswith(name, name_len, "libm.so")) {
        dest = &set->libm;
    } else if (name_endswith(name, name_len, "libdl.so")) {
        dest = &set->libdl;
    } else if (name_endswith(name, name_len, "libart.so")) {
        dest = &set->libart;
    } else if (path_starts_with(name, "/system/") ||
               path_starts_with(name, "/vendor/") ||
               path_starts_with(name, "/apex/") ||
               path_starts_with(name, "/data/dalvik-cache/")) {
        dest = &set->other_system;
    }
    if (dest == nullptr) return 0;
    for (const auto& r : rx_ranges) {
        dest->push_back(r);
    }
    return 0;
}

void initialize_locked() {
    dl_iterate_phdr(&dl_callback, &g_ranges);
    RLOGI(
        "native_integrity: G1 module init libdicore RX [0x%lx, 0x%lx) base=0x%lx",
        static_cast<unsigned long>(g_libdicore.rx_start),
        static_cast<unsigned long>(g_libdicore.rx_end),
        static_cast<unsigned long>(g_libdicore.base_addr)
    );
    RLOGI(
        "native_integrity: G1 ranges libc=%zu libm=%zu libdl=%zu libart=%zu libdicore=%zu other_system=%zu",
        g_ranges.libc.size(),
        g_ranges.libm.size(),
        g_ranges.libdl.size(),
        g_ranges.libart.size(),
        g_ranges.libdicore.size(),
        g_ranges.other_system.size()
    );
}

}  // namespace

const char* region_name(Region r) {
    switch (r) {
        case Region::UNKNOWN:       return "unknown";
        case Region::LIBC:          return "libc";
        case Region::LIBM:          return "libm";
        case Region::LIBDL:         return "libdl";
        case Region::LIBART:        return "libart";
        case Region::LIBDICORE:     return "libdicore";
        case Region::OTHER_SYSTEM:  return "other_system";
    }
    return "unknown";
}

size_t initialize_ranges() {
    std::call_once(g_once, &initialize_locked);
    return g_ranges.libc.size() + g_ranges.libm.size() + g_ranges.libdl.size() +
           g_ranges.libart.size() + g_ranges.libdicore.size() +
           g_ranges.other_system.size();
}

Region classify(const void* addr) {
    initialize_ranges();
    const auto a = reinterpret_cast<uintptr_t>(addr);
    if (addr_in(g_ranges.libdicore, a))    return Region::LIBDICORE;
    if (addr_in(g_ranges.libart, a))       return Region::LIBART;
    if (addr_in(g_ranges.libc, a))         return Region::LIBC;
    if (addr_in(g_ranges.libm, a))         return Region::LIBM;
    if (addr_in(g_ranges.libdl, a))        return Region::LIBDL;
    if (addr_in(g_ranges.other_system, a)) return Region::OTHER_SYSTEM;
    return Region::UNKNOWN;
}

bool is_in_known_image(const void* addr) {
    initialize_ranges();
    const auto a = reinterpret_cast<uintptr_t>(addr);
    return addr_in(g_image_extents, a);
}

bool is_in_trusted_jit_or_oat(const void* addr) {
    // The hardcoded `/apex/`, `/system_ext/`, `[anon:jit-cache]`
    // tables that used to live here have moved to baseline.cpp,
    // which derives the trust set dynamically from the process's
    // own /proc/self/maps at JNI_OnLoad rather than from a
    // checked-in list of OEM partition names. Every lesson we
    // learned the hard way (HyperOS's `[anon_shmem:dalvik-...]`,
    // Pixel 9's `/data/misc/apexdata/`) is now captured
    // automatically from the snapshot.
    return is_address_trusted_via_baseline(reinterpret_cast<uintptr_t>(addr));
}

LibdicoreLayout libdicore_layout() {
    initialize_ranges();
    return g_libdicore;
}

const char* libdicore_path() {
    initialize_ranges();
    return g_libdicore_path[0] != '\0' ? g_libdicore_path : nullptr;
}

size_t libc_range_count()         { initialize_ranges(); return g_ranges.libc.size(); }
size_t libm_range_count()         { initialize_ranges(); return g_ranges.libm.size(); }
size_t libdl_range_count()        { initialize_ranges(); return g_ranges.libdl.size(); }
size_t libart_range_count()       { initialize_ranges(); return g_ranges.libart.size(); }
size_t libdicore_range_count()    { initialize_ranges(); return g_ranges.libdicore.size(); }
size_t other_system_range_count() { initialize_ranges(); return g_ranges.other_system.size(); }

}  // namespace dicore::native_integrity
