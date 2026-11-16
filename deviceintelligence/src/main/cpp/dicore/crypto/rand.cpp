#include "dicore/crypto/rand.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace dicore::crypto {
namespace {

// Use the raw syscall so this links on minSdk 28 without a getrandom() libc stub.
long getrandom_raw(void* buf, size_t buflen, unsigned int flags) {
#if defined(SYS_getrandom)
    return syscall(SYS_getrandom, buf, buflen, flags);
#else
    (void)buf; (void)buflen; (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

bool fill_urandom(uint8_t* out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t off = 0;
    bool ok = true;
    while (off < len) {
        ssize_t n = read(fd, out + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; ok = false; break; }
        if (n == 0) { ok = false; break; }
        off += static_cast<size_t>(n);
    }
    close(fd);
    return ok && off == len;
}

} // namespace

bool secure_random(uint8_t* out, size_t len) {
    if (len == 0) return true;
    if (out == nullptr) return false;
    size_t off = 0;
    while (off < len) {
        long n = getrandom_raw(out + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;                       // ENOSYS / other -> fall through to urandom
        }
        off += static_cast<size_t>(n);
    }
    if (off == len) return true;
    return fill_urandom(out + off, len - off);
}

} // namespace dicore::crypto
