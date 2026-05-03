#include "syscalls.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>

namespace dicore::sys {

namespace {

// Inline-asm syscall stubs. The 64-bit ABIs (aarch64, x86_64) issue
// raw syscalls directly to bypass any libc-level hooks an attacker
// might have installed. The 32-bit ARM (armeabi-v7a) branch
// delegates to libc instead — see the lengthy comment near the
// __arm__ block below for why.

#if defined(__aarch64__)

// aarch64 syscall numbers (asm-generic + arch overrides as used by bionic).
constexpr long NR_openat  = 56;
constexpr long NR_close   = 57;
constexpr long NR_lseek   = 62;
constexpr long NR_read    = 63;
constexpr long NR_fstat   = 80;
constexpr long NR_mmap    = 222;
constexpr long NR_munmap  = 215;

static inline long do_syscall6(long nr,
                               long a0, long a1, long a2,
                               long a3, long a4, long a5) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = a0;
    register long x1 asm("x1") = a1;
    register long x2 asm("x2") = a2;
    register long x3 asm("x3") = a3;
    register long x4 asm("x4") = a4;
    register long x5 asm("x5") = a5;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory", "cc");
    return x0;
}

#elif defined(__x86_64__)

constexpr long NR_openat  = 257;
constexpr long NR_close   = 3;
constexpr long NR_lseek   = 8;
constexpr long NR_read    = 0;
constexpr long NR_fstat   = 5;
constexpr long NR_mmap    = 9;
constexpr long NR_munmap  = 11;

static inline long do_syscall6(long nr,
                               long a0, long a1, long a2,
                               long a3, long a4, long a5) {
    long ret;
    register long r10 asm("r10") = a3;
    register long r8  asm("r8")  = a4;
    register long r9  asm("r9")  = a5;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "0"(nr), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
}

#elif defined(__arm__)

// 32-bit ARM (armeabi-v7a) — delegate to libc rather than issue raw
// syscalls. NO `do_syscall6` / NR_* declarations on this branch:
// the public wrappers below `#if defined(__arm__)` straight into
// libc, and `-Werror -Wunused-*` would reject any unused stubs.
//
// The 32-bit Linux ARM ABI diverges from the 64-bit ABIs in three
// places that are easy to get subtly wrong:
//
//   1. `lseek` takes a 32-bit offset. For 64-bit `off_t` (which
//      Android sets via `_FILE_OFFSET_BITS=64` for our minSdk 28+
//      targets), userspace must call `_llseek` (NR=140) which has
//      a totally different argument layout: `(fd, offset_high,
//      offset_low, *result, whence)`.
//   2. `mmap` legacy form vs `mmap2` (NR=192) which takes offset
//      in 4 KB pages, not bytes — easy to get pgoff/byteoff
//      conversion subtly wrong.
//   3. `fstat` requires `fstat64` (NR=197) on 32-bit — bionic's
//      `struct stat` is internally `stat64`-shaped, so the
//      legacy `fstat` uses an incompatible kernel struct.
//
// Each of these is fixable, but every fix introduces a way for a
// subtle bug to silently corrupt the read. armeabi-v7a is a
// secondary ABI in this library (low-end devices in EM markets,
// already reduced to INCONCLUSIVE for `integrity.art` due to the
// 32-bit ART struct-offset gap) so the security tradeoff is to
// route through libc here. A libc hooker can intercept these
// reads on 32-bit ARM that they cannot on 64-bit; documented in
// docs/DETECTORS.md as part of the armeabi-v7a coverage notes.

#else
#  error "Unsupported architecture for dicore raw syscalls"
#endif

#if !defined(__arm__)

// Translate a kernel return value into (return, errno).
// Kernel returns -errno for errors in the range [-4095, -1]; any other
// negative-looking value (e.g. mmap'ing high addresses on x86_64) is a
// valid result, so we use the unsigned-compare trick.
static inline bool is_kernel_error(long ret) {
    return static_cast<unsigned long>(ret) >= static_cast<unsigned long>(-4096L);
}

#endif  // !defined(__arm__)

} // namespace

int raw_openat(int dirfd, const char* path, int flags, int mode, int* errno_out) {
#if defined(__arm__)
    int r = ::openat(dirfd, path, flags, mode);
    if (r < 0 && errno_out) *errno_out = errno;
    return r;
#else
    long r = do_syscall6(NR_openat,
                         (long)dirfd, (long)path, (long)flags, (long)mode, 0, 0);
    if (is_kernel_error(r)) {
        if (errno_out) *errno_out = (int)(-r);
        return -1;
    }
    return (int)r;
#endif
}

int raw_close(int fd) {
#if defined(__arm__)
    return ::close(fd);
#else
    long r = do_syscall6(NR_close, (long)fd, 0, 0, 0, 0, 0);
    return is_kernel_error(r) ? -1 : 0;
#endif
}

ssize_t raw_read_full(int fd, void* buf, size_t count, int* errno_out) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t total = 0;
    while (total < count) {
#if defined(__arm__)
        ssize_t r = ::read(fd, p + total, count - total);
        if (r < 0) {
            if (errno_out) *errno_out = errno;
            return -1;
        }
        if (r == 0) break; // EOF
        total += (size_t)r;
#else
        long r = do_syscall6(NR_read,
                             (long)fd, (long)(p + total), (long)(count - total),
                             0, 0, 0);
        if (is_kernel_error(r)) {
            if (errno_out) *errno_out = (int)(-r);
            return -1;
        }
        if (r == 0) break; // EOF
        total += (size_t)r;
#endif
    }
    return (ssize_t)total;
}

off_t raw_lseek(int fd, off_t offset, int whence, int* errno_out) {
#if defined(__arm__)
    off_t r = ::lseek(fd, offset, whence);
    if (r == (off_t)-1 && errno_out) *errno_out = errno;
    return r;
#else
    long r = do_syscall6(NR_lseek,
                         (long)fd, (long)offset, (long)whence, 0, 0, 0);
    if (is_kernel_error(r)) {
        if (errno_out) *errno_out = (int)(-r);
        return (off_t)-1;
    }
    return (off_t)r;
#endif
}

int raw_fstat_size(int fd, off_t* out_size, int* errno_out) {
    struct stat st {};
#if defined(__arm__)
    if (::fstat(fd, &st) < 0) {
        if (errno_out) *errno_out = errno;
        return -1;
    }
#else
    long r = do_syscall6(NR_fstat, (long)fd, (long)&st, 0, 0, 0, 0);
    if (is_kernel_error(r)) {
        if (errno_out) *errno_out = (int)(-r);
        return -1;
    }
#endif
    if (out_size) *out_size = (off_t)st.st_size;
    return 0;
}

void* raw_mmap_readonly(size_t length, int fd, off_t offset, int* errno_out) {
#if defined(__arm__)
    void* p = ::mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, offset);
    if (p == MAP_FAILED && errno_out) *errno_out = errno;
    return p;
#else
    long r = do_syscall6(NR_mmap,
                         0,                         // addr = NULL (kernel chooses)
                         (long)length,
                         (long)PROT_READ,
                         (long)MAP_PRIVATE,
                         (long)fd,
                         (long)offset);
    if (is_kernel_error(r)) {
        if (errno_out) *errno_out = (int)(-r);
        return MAP_FAILED;
    }
    return reinterpret_cast<void*>(r);
#endif
}

int raw_munmap(void* addr, size_t length) {
#if defined(__arm__)
    return ::munmap(addr, length);
#else
    long r = do_syscall6(NR_munmap, (long)addr, (long)length, 0, 0, 0, 0);
    return is_kernel_error(r) ? -1 : 0;
#endif
}

} // namespace dicore::sys
