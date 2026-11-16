#include "dicore/platform/safe_text_read.h"

#include <cstdint>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

namespace dicore::platform {

namespace {

// The fd is opened once and kept: JNI_OnLoad snapshots and every later scan read
// through it, and re-opening per call would add an openat to the syscall profile
// for no benefit. O_CLOEXEC so it never leaks across an exec.
int self_mem_fd() {
    static int fd = ::open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    return fd;
}

bool read_via_self_mem(const void* addr, void* out, size_t len) {
    const int fd = self_mem_fd();
    if (fd < 0) return false;
    auto* dst = static_cast<uint8_t*>(out);
    off_t off = static_cast<off_t>(reinterpret_cast<uintptr_t>(addr));
    size_t done = 0;
    while (done < len) {
        const ssize_t n = ::pread(fd, dst + done, len - done, off + static_cast<off_t>(done));
        // 0 means EOF at this offset — the page is not there. Treat like an error
        // rather than spinning.
        if (n <= 0) return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

bool read_via_vm_readv(const void* addr, void* out, size_t len) {
    struct iovec local { out, len };
    struct iovec remote { const_cast<void*>(addr), len };
    return ::process_vm_readv(::getpid(), &local, 1, &remote, 1, 0) ==
           static_cast<ssize_t>(len);
}

}  // namespace

bool safe_read_code(const void* addr, void* out, size_t len) {
    if (addr == nullptr || out == nullptr || len == 0) return false;
    if (read_via_self_mem(addr, out, len)) return true;
    return read_via_vm_readv(addr, out, len);
}

}  // namespace dicore::platform
