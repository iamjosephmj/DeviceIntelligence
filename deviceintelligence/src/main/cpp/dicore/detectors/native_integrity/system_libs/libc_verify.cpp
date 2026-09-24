#include "dicore/detectors/native_integrity/system_libs/libc_verify.h"

#include "dicore/crypto/sha256.h"
#include "dicore/detectors/native_integrity/shared/elf_segment.h"
#include "dicore/platform/safe_text_read.h"
#include "dicore/platform/syscalls.h"

#include <elf.h>
#include <fcntl.h>
#include <link.h>      // dl_iterate_phdr, ElfW, dl_phdr_info
#include <sys/types.h>
#include <cstring>
#include <vector>

namespace dicore::native_integrity {

namespace {

// The live executable segment of a located module.
struct LiveSeg {
    bool found = false;
    uintptr_t base = 0;       // dlpi_addr (load bias)
    uint64_t p_vaddr = 0;
    uint64_t p_filesz = 0;
    char name[512] = {};      // dlpi_name (the linker's path/soname)
};

struct CbArg {
    const char* suffix;
    LiveSeg* out;
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

// Hash a module's live executable segment and the same segment from its on-disk
// file (raw-syscall read), and compare. Currently libc-only (internal linkage);
// the same shape generalises to libart/linker by promoting this to a shared
// header when those detectors are added.
LibcTextStatus verify_module_text(const char* suffix, const char* fallback_path) {
    if (!sha::ensure_initialized()) return LibcTextStatus::kUnavailable;

    LiveSeg live;
    CbArg arg{suffix, &live};
    dl_iterate_phdr(&find_module_cb, &arg);
    if (!live.found || live.p_filesz == 0) return LibcTextStatus::kUnavailable;

    // The live segment CANNOT be hashed in place: Android 10+ arm64 maps system
    // libraries' .text execute-only, and sha256() reading it raises SIGSEGV/
    // SEGV_ACCERR (this killed the scan thread on a Galaxy S9 / star2lte:10).
    // Stage a readable copy via /proc/self/mem, then hash that.
    uint8_t live_hash[sha::kDigestLen];
    std::vector<uint8_t> live_copy(static_cast<size_t>(live.p_filesz));
    if (!platform::safe_read_code(reinterpret_cast<const void*>(live.base + live.p_vaddr),
                                  live_copy.data(), live_copy.size())) {
        // Unreadable -> UNAVAILABLE, the same as a missing segment. A detector that
        // cannot see must not be mistaken for one that saw tampering.
        return LibcTextStatus::kUnavailable;
    }
    if (!sha::sha256(live_copy.data(), live_copy.size(), live_hash))
        return LibcTextStatus::kUnavailable;

    const char* path = (live.name[0] == '/') ? live.name : fallback_path;
    int err = 0;
    int fd = sys::raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, &err);
    if (fd < 0) return LibcTextStatus::kUnavailable;

    LibcTextStatus st = LibcTextStatus::kUnavailable;
    off_t fsize = 0;
    if (sys::raw_fstat_size(fd, &fsize, &err) == 0 && fsize > 0) {
        void* map = sys::raw_mmap_readonly(static_cast<size_t>(fsize), fd, 0, &err);
        if (map) {
            // fva (file p_vaddr) is intentionally unused: the on-disk segment is indexed
            // by file offset (foff); the live segment uses the live p_vaddr.
            uint64_t foff = 0, ffsz = 0, fva = 0;
            if (find_exec_segment(static_cast<const uint8_t*>(map), static_cast<size_t>(fsize),
                                  &foff, &ffsz, &fva) &&
                ffsz == live.p_filesz) {                       // size skew -> fail-open
                uint8_t file_hash[sha::kDigestLen];
                if (sha::sha256(static_cast<const uint8_t*>(map) + foff, ffsz, file_hash)) {
                    st = (std::memcmp(file_hash, live_hash, sha::kDigestLen) == 0)
                             ? LibcTextStatus::kOk
                             : LibcTextStatus::kHashMismatch;
                }
            }
            sys::raw_munmap(map, static_cast<size_t>(fsize));
        }
    }
    sys::raw_close(fd);
    return st;
}

}  // namespace

bool libc_ondisk_bytes(uintptr_t live_addr, uint8_t* out, size_t n) {
    if (!out || n == 0) return false;
#if defined(__LP64__)
    const char* fallback = "/apex/com.android.runtime/lib64/bionic/libc.so";
#else
    const char* fallback = "/apex/com.android.runtime/lib/bionic/libc.so";
#endif
    LiveSeg live;
    CbArg arg{"libc.so", &live};
    dl_iterate_phdr(&find_module_cb, &arg);
    if (!live.found || live.p_filesz == 0) return false;
    const uintptr_t seg_lo = live.base + live.p_vaddr;
    if (live_addr < seg_lo || live_addr + n > seg_lo + live.p_filesz) return false;
    const uint64_t seg_off = static_cast<uint64_t>(live_addr - seg_lo);  // offset within exec segment

    const char* path = (live.name[0] == '/') ? live.name : fallback;
    int err = 0;
    int fd = sys::raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, &err);
    if (fd < 0) return false;
    bool ok = false;
    off_t fsize = 0;
    if (sys::raw_fstat_size(fd, &fsize, &err) == 0 && fsize > 0) {
        void* map = sys::raw_mmap_readonly(static_cast<size_t>(fsize), fd, 0, &err);
        if (map) {
            uint64_t foff = 0, ffsz = 0, fva = 0;
            if (find_exec_segment(static_cast<const uint8_t*>(map), static_cast<size_t>(fsize),
                                  &foff, &ffsz, &fva) &&
                seg_off + n <= ffsz && foff + seg_off + n <= static_cast<uint64_t>(fsize)) {
                std::memcpy(out, static_cast<const uint8_t*>(map) + foff + seg_off, n);
                ok = true;
            }
            sys::raw_munmap(map, static_cast<size_t>(fsize));
        }
    }
    sys::raw_close(fd);
    return ok;
}

LibcTextStatus scan_libc_text() {
#if defined(__LP64__)
    return verify_module_text("libc.so", "/apex/com.android.runtime/lib64/bionic/libc.so");
#else
    return verify_module_text("libc.so", "/apex/com.android.runtime/lib/bionic/libc.so");
#endif
}

const char* libc_text_status_name(LibcTextStatus s) {
    switch (s) {
        case LibcTextStatus::kOk: return "ok";
        case LibcTextStatus::kHashMismatch: return "hash_mismatch";
        default: return "unavailable";
    }
}

}  // namespace dicore::native_integrity
