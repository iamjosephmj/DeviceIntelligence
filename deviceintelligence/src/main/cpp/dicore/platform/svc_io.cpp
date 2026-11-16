// See svc_io.h.
#include "dicore/platform/svc_io.h"

#include "dicore/platform/syscalls.h"

#include <fcntl.h>
#include <unistd.h>

namespace dicore::svc {

namespace {

// ---- libc backend (host tests / non-sensitive paths) ----------------------

int libc_open_ro(const char* path) {
    return ::open(path, O_RDONLY | O_CLOEXEC);
}

ssize_t libc_read(int fd, void* buf, size_t n) { return ::read(fd, buf, n); }

void libc_close(int fd) { ::close(fd); }

// ---- raw-syscall backend (production path for sensitive reads) ------------
// Thin over sys::raw_* — the arch-specific syscall stubs live there, including
// the armeabi-v7a libc delegation. O_CLOEXEC matches the "re" flag every
// converted stdio call site used to pass.

int svc_open_ro(const char* path) {
    return sys::raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, nullptr);
}

ssize_t svc_read(int fd, void* buf, size_t n) {
    return sys::raw_read(fd, buf, n, nullptr);
}

void svc_close(int fd) { sys::raw_close(fd); }

}  // namespace

const Io libc_io{libc_open_ro, libc_read, libc_close};
const Io svc_io{svc_open_ro, svc_read, svc_close};

int open_ro(const char* path) { return svc_io.open_ro(path); }

ssize_t read_full(int fd, void* buf, size_t n) {
    return read_full(svc_io, fd, buf, n);
}

void close_fd(int fd) { svc_io.close(fd); }

ssize_t read_full(const Io& io, int fd, void* buf, size_t n) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t total = 0;
    while (total < n) {
        const ssize_t r = io.read(fd, p + total, n - total);
        if (r < 0) return -1;   // error propagates; caller sees unreadable
        if (r == 0) break;      // EOF: short count, never a spin
        total += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(total);
}

bool read_file(const Io& io, const char* path, std::string* out, size_t cap) {
    out->clear();
    if (path == nullptr) return false;
    const int fd = io.open_ro(path);
    if (fd < 0) return false;

    char chunk[8192];
    bool ok = true;
    while (true) {
        const ssize_t r = io.read(fd, chunk, sizeof(chunk));
        if (r < 0) {
            ok = false;
            break;
        }
        if (r == 0) break;  // EOF
        out->append(chunk, static_cast<size_t>(r));
        if (out->size() > cap) {
            // Oversized sensitive file: fail, don't hand back a partial view.
            ok = false;
            break;
        }
    }
    io.close(fd);
    if (!ok) out->clear();
    return ok;
}

bool exists(const Io& io, const char* path) {
    if (path == nullptr) return false;
    const int fd = io.open_ro(path);
    if (fd < 0) return false;
    io.close(fd);
    return true;
}

}  // namespace dicore::svc
