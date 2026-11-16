#include "dicore/detectors/native_integrity/self/got_sections.h"

#include "dicore/detectors/native_integrity/process/range_map.h"
#include "dicore/platform/log.h"
#include "dicore/platform/svc_io.h"
#include "dicore/platform/syscalls.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace dicore::native_integrity {
namespace {

using Elf64_Shdr_t = ElfW(Shdr);
using Elf64_Ehdr_t = ElfW(Ehdr);

/** Locate `.got` and `.got.plt` by name in the ELF section header table.
 * Returns false on any parse failure (file too small, stripped, malformed). */
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
        return false;  // stripped (no section headers in the file)
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
        if (shdr.sh_addr == 0) continue;  // non-alloc section (.symtab/.strtab)
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

/** File offset (p_offset) of libdicore's executable PT_LOAD — used to translate
 * "RX segment offset within the APK" back to "ELF start within the APK".
 * Virtually always 0 for an NDK .so, but read explicitly for robustness. */
size_t libdicore_rx_segment_p_offset() {
    struct Ctx { bool found; size_t p_offset; };
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

// Where libdicore's ELF actually lives on disk. On modern Android
// (extractNativeLibs=false) libdicore_path() is a compound
// "<apk>!/lib/<abi>/libdicore.so" that open(2) can't use directly; on legacy
// installs it's a plain openable path.
struct DiscView {
    std::string path;
    bool        is_apk;
    off_t       elf_offset_in_apk;  // 0 when is_apk == false
};

bool resolve_apk_view(const char* compound_path, DiscView* out) {
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

    // B3: raw-syscall read — this is the /proc half of locating OUR OWN
    // on-disk image inside the APK; a hooked stdio layer could point the
    // ELF-offset math at the wrong mapping and make the G4 diff vacuous.
    std::string maps;
    if (!svc::read_file("/proc/self/maps", &maps)) return false;
    bool found = false;
    svc::LineCursor cur(maps);
    std::string line;
    while (cur.next(&line)) {
        unsigned long start = 0, end = 0, offset = 0;
        char perms[5] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        int consumed = 0;
        if (std::sscanf(line.c_str(), "%lx-%lx %4s %lx %15s %lu %n",
                        &start, &end, perms, &offset, dev, &inode,
                        &consumed) < 6) continue;
        if (perms[0] != 'r' || perms[2] != 'x') continue;
        if (start != layout.rx_start) continue;
        const size_t rx_p_offset = libdicore_rx_segment_p_offset();
        if (offset < rx_p_offset) break;  // inconsistent; not page-aligned
        out->elf_offset_in_apk = static_cast<off_t>(offset - rx_p_offset);
        found = true;
        break;
    }
    return found;
}

}  // namespace

bool locate_got_sections(uintptr_t base_addr, const char* compound_path,
                         GotSection* got, GotSection* got_plt) {
    if (compound_path == nullptr) return false;
    DiscView view{};
    if (!resolve_apk_view(compound_path, &view)) {
        RLOGW("native_integrity: G4 locate: could not resolve disk view for %s", compound_path);
        return false;
    }
    // B3: raw syscalls for the app-file integrity read — this mmaps OUR OWN
    // APK to diff the on-disk GOT against the live one; a libc PLT hook on
    // open/fstat/mmap could serve a pristine cached file and hide every
    // runtime GOT patch G4 exists to catch.
    int err = 0;
    int fd = sys::raw_openat(AT_FDCWD, view.path.c_str(), O_RDONLY | O_CLOEXEC, 0, &err);
    if (fd < 0) {
        RLOGW("native_integrity: G4 locate: open(%s) failed errno=%d", view.path.c_str(), err);
        return false;
    }
    off_t file_size = 0;
    if (sys::raw_fstat_size(fd, &file_size, &err) != 0 || file_size <= 0) {
        sys::raw_close(fd);
        RLOGW("native_integrity: G4 locate: fstat failed errno=%d", err);
        return false;
    }
    const size_t apk_size = static_cast<size_t>(file_size);
    if (view.is_apk &&
        (view.elf_offset_in_apk < 0 ||
         static_cast<size_t>(view.elf_offset_in_apk) >= apk_size)) {
        sys::raw_close(fd);
        RLOGW("native_integrity: G4 locate: invalid ELF offset %lld within APK (size=%zu)",
              static_cast<long long>(view.elf_offset_in_apk), apk_size);
        return false;
    }
    const off_t mmap_offset = view.is_apk ? view.elf_offset_in_apk : 0;
    const size_t mmap_size = apk_size - static_cast<size_t>(mmap_offset);
    void* mapping = sys::raw_mmap_readonly(mmap_size, fd, mmap_offset, &err);
    sys::raw_close(fd);
    if (mapping == MAP_FAILED) {
        RLOGW("native_integrity: G4 locate: mmap libdicore failed errno=%d", err);
        return false;
    }
    bool found = find_got_sections_from_file(
        static_cast<const uint8_t*>(mapping), mmap_size, base_addr, got, got_plt);
    sys::raw_munmap(mapping, mmap_size);
    if (!found) {
        RLOGW("native_integrity: G4 locate: no .got/.got.plt in libdicore "
              "(stripped or unrecognised ELF layout)");
    }
    return found;
}

}  // namespace dicore::native_integrity
