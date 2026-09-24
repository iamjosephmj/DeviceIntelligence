// Host unit test for the pure ELF exec-segment finder (no JNI/syscalls).
// Build/run command at the bottom. Mirrors test_seccomp_verdict.cpp's approach.
#include "dicore/detectors/native_integrity/shared/elf_segment.h"

#include <elf.h>
#include <link.h>   // ElfW
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    using namespace dicore::native_integrity;

    // Minimal ELF: Ehdr + 2 program headers (PT_LOAD R, then PT_LOAD R+X).
    std::vector<uint8_t> buf(4096, 0);
    auto* eh = reinterpret_cast<ElfW(Ehdr)*>(buf.data());
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
#if defined(__LP64__)
    eh->e_ident[EI_CLASS] = ELFCLASS64;
#else
    eh->e_ident[EI_CLASS] = ELFCLASS32;
#endif
    eh->e_phoff = sizeof(ElfW(Ehdr));
    eh->e_phnum = 2;
    eh->e_phentsize = sizeof(ElfW(Phdr));
    auto* ph = reinterpret_cast<ElfW(Phdr)*>(buf.data() + eh->e_phoff);
    ph[0].p_type = PT_LOAD; ph[0].p_flags = PF_R;        ph[0].p_offset = 0;     ph[0].p_filesz = 0x100; ph[0].p_vaddr = 0;
    ph[1].p_type = PT_LOAD; ph[1].p_flags = PF_R | PF_X; ph[1].p_offset = 0x200; ph[1].p_filesz = 0x400; ph[1].p_vaddr = 0x1200;

    uint64_t off = 0, fsz = 0, va = 0;
    assert(find_exec_segment(buf.data(), buf.size(), &off, &fsz, &va));
    assert(off == 0x200 && fsz == 0x400 && va == 0x1200);   // picks the PF_X segment

    // Not an ELF -> false.
    std::vector<uint8_t> junk(128, 0xAB);
    assert(!find_exec_segment(junk.data(), junk.size(), &off, &fsz, &va));

    // Valid magic but wrong ELF class for this build -> rejected.
    {
        std::vector<uint8_t> wrong = buf;  // copy the otherwise-valid ELF
        auto* weh = reinterpret_cast<ElfW(Ehdr)*>(wrong.data());
#if defined(__LP64__)
        weh->e_ident[EI_CLASS] = ELFCLASS32;
#else
        weh->e_ident[EI_CLASS] = ELFCLASS64;
#endif
        assert(!find_exec_segment(wrong.data(), wrong.size(), &off, &fsz, &va));
    }

    // Valid header but zero program headers -> rejected.
    {
        std::vector<uint8_t> noph = buf;  // copy a known-valid ELF
        reinterpret_cast<ElfW(Ehdr)*>(noph.data())->e_phnum = 0;
        assert(!find_exec_segment(noph.data(), noph.size(), &off, &fsz, &va));
    }

    // PF_X segment claims to run past the file -> false (bounds check).
    ph[1].p_filesz = 0x100000;
    assert(!find_exec_segment(buf.data(), buf.size(), &off, &fsz, &va));

    printf("all elf_segment tests passed\n");
    return 0;
}
// Build & run (host):
//   clang++ -std=c++17 -I deviceintelligence/src/main/cpp \
//     deviceintelligence/src/main/cpp/dicore/detectors/native_integrity/test_elf_segment.cpp \
//     deviceintelligence/src/main/cpp/dicore/detectors/native_integrity/shared/elf_segment.cpp \
//     -o /tmp/test_elfseg && /tmp/test_elfseg
