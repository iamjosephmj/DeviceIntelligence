#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dicore {

// RAII handle around (raw_openat + raw_mmap) of a file. Opens the file
// read-only via direct syscall, mmap's the entire file, and unmaps on dtor.
// Used to read APK bytes from the kernel without going through any libc
// open()/mmap() PLT entry.
class ApkMap {
public:
    ApkMap() = default;
    ~ApkMap();

    ApkMap(const ApkMap&)            = delete;
    ApkMap& operator=(const ApkMap&) = delete;
    ApkMap(ApkMap&& other) noexcept;
    ApkMap& operator=(ApkMap&& other) noexcept;

    // Open and mmap. Returns true on success; on failure populates
    // last_error() with a short reason and a positive errno code (0 if
    // the failure didn't come from a syscall).
    bool open(const char* path);

    // Wrap an already-resident, caller-owned buffer (NOT mmap'd, NOT freed by
    // this object). Used by the fuzz harness to drive the ZIP/signing-block
    // parsers over arbitrary in-memory bytes without a file round-trip; the
    // buffer must outlive this ApkMap.
    bool open_memory(const uint8_t* data, size_t len);

    [[nodiscard]] const uint8_t* data() const { return base_; }
    [[nodiscard]] size_t         size() const { return length_; }
    [[nodiscard]] bool           is_open() const { return base_ != nullptr; }

    [[nodiscard]] const std::string& last_error() const { return last_error_; }
    [[nodiscard]] int                last_errno() const { return last_errno_; }

    // Bounded sub-buffer accessor with overflow-safe bounds check.
    // Returns nullptr if [offset, offset+len) is out of range.
    const uint8_t* range(size_t offset, size_t len) const;

private:
    void close();

    uint8_t*    base_   = nullptr;
    size_t      length_ = 0;
    int         fd_     = -1;
    bool        borrowed_ = false;  // true => base_ is caller-owned, do not munmap
    std::string last_error_;
    int         last_errno_ = 0;
};

} // namespace dicore
