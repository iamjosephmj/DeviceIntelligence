#include "dicore/detectors/apk/container/apkmap.h"

#include "dicore/platform/log.h"
#include "dicore/platform/syscalls.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <utility>

namespace dicore {

ApkMap::~ApkMap() { close(); }

ApkMap::ApkMap(ApkMap&& other) noexcept {
    *this = std::move(other);
}

ApkMap& ApkMap::operator=(ApkMap&& other) noexcept {
    if (this != &other) {
        close();
        base_       = other.base_;
        length_     = other.length_;
        fd_         = other.fd_;
        borrowed_   = other.borrowed_;
        last_error_ = std::move(other.last_error_);
        last_errno_ = other.last_errno_;
        other.base_       = nullptr;
        other.length_     = 0;
        other.fd_         = -1;
        other.borrowed_   = false;
        other.last_errno_ = 0;
    }
    return *this;
}

bool ApkMap::open(const char* path) {
    close();
    if (!path || !*path) {
        last_error_ = "empty path";
        return false;
    }

    int err = 0;
    int fd  = sys::raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, &err);
    if (fd < 0) {
        last_error_ = "openat failed";
        last_errno_ = err;
        return false;
    }

    off_t size = 0;
    if (sys::raw_fstat_size(fd, &size, &err) != 0 || size <= 0) {
        last_error_ = "fstat failed";
        last_errno_ = err;
        sys::raw_close(fd);
        return false;
    }

    void* m = sys::raw_mmap_readonly((size_t)size, fd, 0, &err);
    if (m == MAP_FAILED) {
        last_error_ = "mmap failed";
        last_errno_ = err;
        sys::raw_close(fd);
        return false;
    }

    base_   = static_cast<uint8_t*>(m);
    length_ = (size_t)size;
    fd_     = fd;
    return true;
}

bool ApkMap::open_memory(const uint8_t* data, size_t len) {
    close();
    if (!data || len == 0) {
        last_error_ = "empty buffer";
        return false;
    }
    // const_cast is safe: borrowed_ buffers are never written or freed here, and
    // all accessors return const pointers.
    base_     = const_cast<uint8_t*>(data);
    length_   = len;
    fd_       = -1;
    borrowed_ = true;
    return true;
}

const uint8_t* ApkMap::range(size_t offset, size_t len) const {
    if (!base_) return nullptr;
    if (offset > length_) return nullptr;
    if (len > length_ - offset) return nullptr; // overflow-safe
    return base_ + offset;
}

void ApkMap::close() {
    if (base_) {
        if (!borrowed_) sys::raw_munmap(base_, length_);  // never unmap borrowed buffers
        base_     = nullptr;
        length_   = 0;
        borrowed_ = false;
    }
    if (fd_ >= 0) {
        sys::raw_close(fd_);
        fd_ = -1;
    }
}

} // namespace dicore
