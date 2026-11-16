#include "dicore/detectors/native_integrity/shared/elf_segment.h"

#include <elf.h>
#include <link.h>  // ElfW(...)
#include <cstring>

namespace dicore::native_integrity {

bool find_exec_segment(const uint8_t* buf, size_t len,
                       uint64_t* out_offset, uint64_t* out_filesz, uint64_t* out_vaddr) {
    if (!buf || len < sizeof(ElfW(Ehdr))) return false;
    const auto* eh = reinterpret_cast<const ElfW(Ehdr)*>(buf);
    if (std::memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return false;
#if defined(__LP64__)
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return false;
#else
    if (eh->e_ident[EI_CLASS] != ELFCLASS32) return false;
#endif

    const size_t phoff = static_cast<size_t>(eh->e_phoff);
    const size_t phnum = static_cast<size_t>(eh->e_phnum);
    const size_t phentsize = static_cast<size_t>(eh->e_phentsize);
    if (phentsize < sizeof(ElfW(Phdr)) || phnum == 0) return false;
    if (phoff >= len) return false;
    if (phnum > (len - phoff) / phentsize) return false;  // program-header table within bounds

    for (size_t i = 0; i < phnum; ++i) {
        const auto* ph = reinterpret_cast<const ElfW(Phdr)*>(buf + phoff + i * phentsize);
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        const uint64_t off = static_cast<uint64_t>(ph->p_offset);
        const uint64_t fsz = static_cast<uint64_t>(ph->p_filesz);
        if (off > len || fsz > len - off) return false;   // segment within file
        *out_offset = off;
        *out_filesz = fsz;
        *out_vaddr = static_cast<uint64_t>(ph->p_vaddr);
        return true;
    }
    return false;
}

}  // namespace dicore::native_integrity
