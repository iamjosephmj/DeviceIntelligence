#include "got_verify.h"

#include "../log.h"
#include "../sha256.h"
#include "range_map.h"

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

namespace dicore::native_integrity {

namespace {

// 64-bit ELF section header layout. ARM64 + x86_64 are both
// 64-bit ELF; we never ship a 32-bit `.so` (build.gradle sets
// abiFilters to arm64-v8a + x86_64 only). 32-bit support would
// just need a parallel Elf32_Shdr path — defer that until/if
// 32-bit ABIs are reintroduced.
using Elf64_Shdr_t = ElfW(Shdr);
using Elf64_Ehdr_t = ElfW(Ehdr);

struct GotSection {
    uintptr_t addr_in_image;  // dlpi_addr + sh_addr
    size_t    bytes;
    size_t    slot_count;
    bool      valid;
};

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
struct BaselineStorage {
    void* values_page = nullptr;
    void* hash_page = nullptr;
    size_t page_size = 0;
    size_t snapshot_bytes = 0;   // (slots * sizeof(uintptr_t))
};
BaselineStorage g_storage;

bool ensure_pages_allocated(size_t bytes_needed) {
    if (g_storage.values_page != nullptr) return true;
    g_storage.page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    if (g_storage.page_size == 0) g_storage.page_size = 4096;
    // Round up to whole pages so we can mprotect the region.
    size_t pages = (bytes_needed + g_storage.page_size - 1) / g_storage.page_size;
    if (pages == 0) pages = 1;
    const size_t total = pages * g_storage.page_size;
    auto map_region = [&](size_t sz) -> void* {
        void* p = ::mmap(nullptr, sz,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (p == MAP_FAILED) ? nullptr : p;
    };
    g_storage.values_page = map_region(total);
    if (!g_storage.values_page) {
        RLOGE("native_integrity: G4 mmap values_page failed errno=%d", errno);
        return false;
    }
    g_storage.hash_page = map_region(g_storage.page_size);
    if (!g_storage.hash_page) {
        ::munmap(g_storage.values_page, total);
        g_storage.values_page = nullptr;
        RLOGE("native_integrity: G4 mmap hash_page failed errno=%d", errno);
        return false;
    }
    std::memset(g_storage.values_page, 0, total);
    std::memset(g_storage.hash_page, 0, g_storage.page_size);
    g_storage.snapshot_bytes = total;
    return true;
}

bool unprotect_baseline() {
    if (!g_storage.values_page || !g_storage.hash_page) return false;
    if (::mprotect(g_storage.values_page, g_storage.snapshot_bytes,
                   PROT_READ | PROT_WRITE) != 0) return false;
    if (::mprotect(g_storage.hash_page, g_storage.page_size,
                   PROT_READ | PROT_WRITE) != 0) {
        ::mprotect(g_storage.values_page, g_storage.snapshot_bytes, PROT_NONE);
        return false;
    }
    return true;
}

void reprotect_baseline() {
    if (!g_storage.values_page || !g_storage.hash_page) return;
    ::mprotect(g_storage.values_page, g_storage.snapshot_bytes, PROT_NONE);
    ::mprotect(g_storage.hash_page, g_storage.page_size, PROT_NONE);
}

/** Locate `.got` and `.got.plt` by name in the ELF section header
 * table. Returns false on any parse failure (file too small,
 * stripped, malformed). */
bool find_got_sections_from_file(
        const uint8_t* file, size_t file_len,
        uintptr_t dlpi_addr,
        GotSection* got, GotSection* got_plt) {
    *got = {};
    *got_plt = {};
    if (file_len < sizeof(Elf64_Ehdr_t)) return false;
    Elf64_Ehdr_t ehdr{};
    std::memcpy(&ehdr, file, sizeof(ehdr));

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        return false;
    }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return false;
    if (ehdr.e_shoff == 0 || ehdr.e_shentsize == 0 || ehdr.e_shnum == 0) {
        // Stripped library (no section headers in the file).
        return false;
    }
    const size_t shtab_end = ehdr.e_shoff + (size_t)ehdr.e_shnum * ehdr.e_shentsize;
    if (shtab_end > file_len) return false;
    if (ehdr.e_shstrndx >= ehdr.e_shnum) return false;

    auto read_shdr = [&](size_t i, Elf64_Shdr_t* out_shdr) -> bool {
        const size_t off = ehdr.e_shoff + i * ehdr.e_shentsize;
        if (off + sizeof(Elf64_Shdr_t) > file_len) return false;
        std::memcpy(out_shdr, file + off, sizeof(Elf64_Shdr_t));
        return true;
    };

    Elf64_Shdr_t strhdr{};
    if (!read_shdr(ehdr.e_shstrndx, &strhdr)) return false;
    if (strhdr.sh_offset + strhdr.sh_size > file_len) return false;
    const char* strtab = reinterpret_cast<const char*>(file + strhdr.sh_offset);

    for (size_t i = 0; i < ehdr.e_shnum; ++i) {
        Elf64_Shdr_t shdr{};
        if (!read_shdr(i, &shdr)) continue;
        if (shdr.sh_name >= strhdr.sh_size) continue;
        const char* name = strtab + shdr.sh_name;
        // sh_addr 0 means the section won't be loaded — skip
        // (typical for non-alloc sections like .symtab, .strtab).
        if (shdr.sh_addr == 0) continue;
        // Slots are 8 bytes wide on 64-bit.
        const size_t slots = shdr.sh_size / sizeof(uintptr_t);
        if (slots == 0) continue;

        if (std::strcmp(name, ".got") == 0 && !got->valid) {
            got->addr_in_image = dlpi_addr + shdr.sh_addr;
            got->bytes = shdr.sh_size;
            got->slot_count = slots;
            got->valid = true;
        } else if (std::strcmp(name, ".got.plt") == 0 && !got_plt->valid) {
            got_plt->addr_in_image = dlpi_addr + shdr.sh_addr;
            got_plt->bytes = shdr.sh_size;
            got_plt->slot_count = slots;
            got_plt->valid = true;
        }
    }
    return got->valid || got_plt->valid;
}

/**
 * Walks libdicore's program-header table and returns the file
 * offset (`p_offset`) of its executable PT_LOAD. Used to translate
 * "RX segment offset within the APK" (read from /proc/self/maps)
 * back to "ELF start within the APK".
 *
 * For an ARM64 / x86_64 `.so` from the NDK this is virtually always
 * zero (RX is the first PT_LOAD), but reading it explicitly lets
 * us survive any toolchain that ever rearranges segments.
 */
size_t libdicore_rx_segment_p_offset() {
    struct Ctx {
        bool found;
        size_t p_offset;
    };
    Ctx ctx{false, 0};
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t /*sz*/, void* user) -> int {
        auto* c = reinterpret_cast<Ctx*>(user);
        if (c->found) return 1;
        if (!info->dlpi_name) return 0;
        const char* name = info->dlpi_name;
        const size_t name_len = std::strlen(name);
        constexpr const char kSuffix[] = "libdicore.so";
        constexpr size_t kSuffixLen = sizeof(kSuffix) - 1;
        if (name_len < kSuffixLen) return 0;
        if (std::strcmp(name + name_len - kSuffixLen, kSuffix) != 0) return 0;
        for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
            const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
            if (phdr.p_type != PT_LOAD) continue;
            if ((phdr.p_flags & PF_X) == 0) continue;
            c->p_offset = static_cast<size_t>(phdr.p_offset);
            c->found = true;
            return 1;
        }
        return 1;
    }, &ctx);
    return ctx.found ? ctx.p_offset : 0;
}

/**
 * On modern Android (`extractNativeLibs=false`, the default since
 * AGP 4.0) `libdicore_path()` returns the linker's compound name
 * `/data/app/.../base.apk!/lib/<abi>/libdicore.so`. `open(2)` does
 * not understand the `!/` separator — it just returns ENOENT.
 *
 * On legacy installs (`extractNativeLibs=true`, or pre-AGP-4.0)
 * the linker hands back an absolute path under
 * `/data/app/.../lib/<abi>/libdicore.so` that `open(2)` accepts
 * directly.
 *
 * This helper teases the two layouts apart and returns:
 *   - [is_apk] = false → [path] is openable; ELF starts at offset 0,
 *                       length is the file size.
 *   - [is_apk] = true  → [path] is the APK; the ELF for libdicore.so
 *                       starts at [elf_offset_in_apk] inside it.
 *                       (Length is the APK file size; the ELF is
 *                       contiguous from elf_offset_in_apk through
 *                       the end of the entry. We mmap conservatively
 *                       up to the file end and only touch what we
 *                       need.)
 */
struct DiscView {
    std::string path;
    bool        is_apk;
    off_t       elf_offset_in_apk;  // 0 when is_apk == false
};

bool resolve_apk_view(const char* compound_path, DiscView* out) {
    // Compound looks like "<apk>!/lib/<abi>/libdicore.so". Split.
    const char* bang = std::strstr(compound_path, "!/");
    if (bang == nullptr) {
        out->path = compound_path;
        out->is_apk = false;
        out->elf_offset_in_apk = 0;
        return true;
    }
    out->path.assign(compound_path, static_cast<size_t>(bang - compound_path));
    out->is_apk = true;
    out->elf_offset_in_apk = -1;  // resolved below from /proc/self/maps

    const auto layout = libdicore_layout();
    if (layout.rx_start == 0) return false;

    // The linker mmap'd the APK at some page-aligned `offset` to
    // produce the RX segment of libdicore. Find that line in
    // /proc/self/maps:
    //   <start>-<end> r-xp <offset> <dev> <inode>   <path>
    // where <start> == layout.rx_start and <path> ends with
    // out->path (we compare suffix to be tolerant of any
    // trailing whitespace / `(deleted)` markers).
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[4096];
    bool found = false;
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, offset = 0;
        char perms[5] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        int consumed = 0;
        if (std::sscanf(line, "%lx-%lx %4s %lx %15s %lu %n",
                        &start, &end, perms, &offset, dev, &inode,
                        &consumed) < 6) continue;
        if (perms[0] != 'r' || perms[2] != 'x') continue;
        if (start != layout.rx_start) continue;

        // The linker's segment offset minus the segment's
        // p_offset within the ELF gives the ELF start within
        // the APK. (For nearly every NDK-built .so p_offset == 0
        // for the RX segment, so this becomes a no-op, but we
        // compute it explicitly to be robust.)
        const size_t rx_p_offset = libdicore_rx_segment_p_offset();
        if (offset < rx_p_offset) {
            // Inconsistent — fall through to fail; mmap won't
            // be at a page boundary.
            break;
        }
        out->elf_offset_in_apk = static_cast<off_t>(offset - rx_p_offset);
        found = true;
        break;
    }
    std::fclose(f);
    return found;
}

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

    DiscView view{};
    if (!resolve_apk_view(compound_path, &view)) {
        RLOGW("native_integrity: G4 init: could not resolve disk view for %s", compound_path);
        return;
    }

    int fd = ::open(view.path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        RLOGW("native_integrity: G4 init: open(%s) failed errno=%d", view.path.c_str(), errno);
        return;
    }
    struct stat st{};
    if (::fstat(fd, &st) != 0 || st.st_size <= 0) {
        ::close(fd);
        RLOGW("native_integrity: G4 init: fstat failed errno=%d", errno);
        return;
    }
    const size_t apk_size = static_cast<size_t>(st.st_size);
    if (view.is_apk &&
        (view.elf_offset_in_apk < 0 ||
         static_cast<size_t>(view.elf_offset_in_apk) >= apk_size)) {
        ::close(fd);
        RLOGW(
            "native_integrity: G4 init: invalid ELF offset %lld within APK (size=%zu)",
            static_cast<long long>(view.elf_offset_in_apk), apk_size
        );
        return;
    }
    // For the in-APK case we mmap from elf_offset_in_apk through
    // the end of the APK; the ELF entry sits contiguously there
    // (zipalign + Android Gradle Plugin guarantee a page-aligned
    // uncompressed STORED entry). For the legacy / extracted
    // case we mmap from offset 0 with the full file size.
    const off_t mmap_offset = view.is_apk ? view.elf_offset_in_apk : 0;
    const size_t mmap_size = apk_size - static_cast<size_t>(mmap_offset);
    void* mapping = ::mmap(nullptr, mmap_size, PROT_READ, MAP_PRIVATE, fd, mmap_offset);
    ::close(fd);
    if (mapping == MAP_FAILED) {
        RLOGW("native_integrity: G4 init: mmap libdicore failed errno=%d", errno);
        return;
    }

    GotSection got{}, got_plt{};
    bool found = find_got_sections_from_file(
        static_cast<const uint8_t*>(mapping), mmap_size,
        layout.base_addr, &got, &got_plt);
    ::munmap(mapping, mmap_size);
    if (!found) {
        RLOGW("native_integrity: G4 init: no .got/.got.plt sections found in libdicore "
              "(stripped or unrecognised ELF layout)");
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
    if (!ensure_pages_allocated(bytes)) {
        // Snapshot still kept in RW vector; we lose the audit but
        // the comparison still works.
        g_state.initialized = true;
        RLOGW("native_integrity: G4 init: PROT_NONE storage unavailable, snapshot in RW");
        return;
    }
    if (!unprotect_baseline()) {
        g_state.initialized = true;
        RLOGW("native_integrity: G4 init: mprotect toggle failed");
        return;
    }
    std::memcpy(g_storage.values_page, g_state.snapshot.data(), bytes);
    uint8_t hh[32] = {};
    if (sha::sha256(g_storage.values_page, bytes, hh)) {
        std::memcpy(g_storage.hash_page, hh, sizeof(hh));
    }
    reprotect_baseline();
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
    bool baseline_intact = true;
    if (g_storage.values_page != nullptr) {
        if (unprotect_baseline()) {
            const size_t bytes = g_state.snapshot.size() * sizeof(uintptr_t);
            uint8_t hh_now[32] = {};
            if (sha::sha256(g_storage.values_page, bytes, hh_now)) {
                baseline_intact = std::memcmp(hh_now, g_storage.hash_page, sizeof(hh_now)) == 0;
            } else {
                baseline_intact = false;
            }
            // We use the in-RAM `g_state.snapshot` for compare;
            // the PROT_NONE page is the audit, not the source of
            // truth. But if the audit fails we disable G4 for
            // this scan to avoid emitting false positives based
            // on a tampered baseline.
            reprotect_baseline();
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
