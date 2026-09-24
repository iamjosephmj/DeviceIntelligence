#include "dicore/detectors/native_integrity/shared/module_text.h"

#include "dicore/detectors/native_integrity/shared/elf_segment.h"
#include "dicore/platform/syscalls.h"

#include <elf.h>
#include <fcntl.h>
#include <link.h>      // dl_iterate_phdr, ElfW, dl_phdr_info
#include <sys/types.h>
#include <cstring>

namespace dicore::native_integrity {

namespace {

struct CbArg {
    const char* suffix;
    LiveExecSeg* out;
};

bool name_ends_with(const char* s, const char* suffix) {
    if (!s) return false;
    const size_t ls = std::strlen(s), lf = std::strlen(suffix);
    return ls >= lf && std::memcmp(s + ls - lf, suffix, lf) == 0;
}

int find_module_cb(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    auto* arg = static_cast<CbArg*>(data);
    if (!info->dlpi_name || !name_ends_with(info->dlpi_name, arg->suffix)) return 0;
    for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) {
            arg->out->found = true;
            arg->out->base = static_cast<uintptr_t>(info->dlpi_addr);
            arg->out->p_vaddr = static_cast<uint64_t>(ph.p_vaddr);
            arg->out->p_filesz = static_cast<uint64_t>(ph.p_filesz);
            std::strncpy(arg->out->name, info->dlpi_name, sizeof(arg->out->name) - 1);
            return 1;  // stop iterating
        }
    }
    return 1;  // matched the module but no PF_X segment; stop (found stays false)
}

}  // namespace

bool find_live_exec_seg(const char* suffix, LiveExecSeg* out) {
    if (!suffix || !out) return false;
    CbArg arg{suffix, out};
    ::dl_iterate_phdr(&find_module_cb, &arg);
    return out->found && out->p_filesz != 0;
}

bool open_disk_exec_seg(const char* path, DiskExecSeg* out) {
    if (!path || !out) return false;
    *out = DiskExecSeg{};

    int err = 0;
    const int fd = sys::raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, &err);
    if (fd < 0) return false;

    bool ok = false;
    off_t fsize = 0;
    if (sys::raw_fstat_size(fd, &fsize, &err) == 0 && fsize > 0) {
        void* map = sys::raw_mmap_readonly(static_cast<size_t>(fsize), fd, 0, &err);
        if (map) {
            uint64_t foff = 0, ffsz = 0, fva = 0;
            if (find_exec_segment(static_cast<const uint8_t*>(map), static_cast<size_t>(fsize),
                                  &foff, &ffsz, &fva) &&
                foff + ffsz <= static_cast<uint64_t>(fsize)) {
                out->map = map;
                out->map_len = static_cast<size_t>(fsize);
                out->text = static_cast<const uint8_t*>(map) + foff;
                out->filesz = ffsz;
                ok = true;
            } else {
                sys::raw_munmap(map, static_cast<size_t>(fsize));
            }
        }
    }
    sys::raw_close(fd);
    return ok;
}

void close_disk_exec_seg(DiskExecSeg* seg) {
    if (!seg || !seg->map) return;
    sys::raw_munmap(seg->map, seg->map_len);
    *seg = DiskExecSeg{};
}

}  // namespace dicore::native_integrity
