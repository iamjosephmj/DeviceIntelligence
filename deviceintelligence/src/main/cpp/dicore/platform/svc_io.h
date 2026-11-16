#pragma once

#include <cstddef>
#include <string>
#include <sys/types.h>

// Direct-svc io for sensitive reads (so-hardening B3).
//
// Every read of a file whose contents steer a detector verdict — /proc/self/*
// (maps, mountinfo, net/unix) and the app's own APK/lib files — must bypass
// libc's PLT: an in-process attacker (Frida, a hooked loader) interposes
// fopen/fgets/read and feeds a sanitized file to whichever probe still routes
// through libc, selectively blinding exactly the detector that caught them.
// The raw-syscall backend below enters the kernel directly (`svc #0` on
// aarch64, `syscall` on x86_64) via dicore/platform/syscalls.h — there is
// no libc symbol left to hook. (armeabi-v7a degrades to libc inside
// syscalls.cpp; a documented coverage limitation of that secondary ABI.)
//
// To keep that state machine honest on the host, the backend is injectable:
// `struct Io` carries the three primitives, the read loops below are PURE
// logic over any Io, and the host suite (test/platform/test_svc_io.cpp) runs
// the same machine through the libc backend, the svc backend, and a
// one-byte-at-a-time backend that proves partial-read retry. On-device proof
// that the aarch64 svc path reads real /proc files lands with Task 7.

namespace dicore::svc {

// Backend vtable. Members map 1:1 to open(2)/read(2)/close(2) semantics:
//   open_ro -> fd >= 0, or -1 on failure
//   read    -> -1 error, 0 EOF, >0 possibly-partial byte count
//   close   -> void (a failed close of a read-only fd is unactionable)
struct Io {
    int (*open_ro)(const char* path);
    ssize_t (*read)(int fd, void* buf, size_t n);
    void (*close)(int fd);
};

// libc backend — for host tests and genuinely non-sensitive paths only.
extern const Io libc_io;
// Raw-syscall backend — the production path for sensitive reads.
extern const Io svc_io;

// Brief-mandated free functions (svc backend):
int     open_ro(const char* path);
ssize_t read_full(int fd, void* buf, size_t n);
void    close_fd(int fd);

// Default cap for read_file: generous vs the largest /proc/self/maps seen in
// the field, but finite — see read_file.
constexpr size_t kDefaultReadCap = 8u << 20;

// Pure state machine: read up to [n] bytes from [fd], retrying partial reads
// until the buffer is full or EOF. Returns the byte count (< n at EOF) or -1
// on error. Identical logic for every backend.
ssize_t read_full(const Io& io, int fd, void* buf, size_t n);

// Pure state machine: whole-file read of [path] through [io] into [out]
// (cleared on entry). Returns false — with [out] left empty — when the file
// cannot be opened, a read errors, or the file exceeds [cap] bytes. A cap
// breach is an ERROR, not a truncation: handing a caller a silently short
// /proc/self/maps would make every maps-based detector half-blind, which is
// precisely the failure mode this layer exists to prevent. Callers already
// degrade to "unreadable" (no signal) on false, which fails safe.
bool read_file(const Io& io, const char* path, std::string* out,
               size_t cap = kDefaultReadCap);

// Pure existence probe over any Io: open read-only; fd >= 0 means present
// (files and directories alike — matching access(F_OK) semantics for the
// directory-shaped probes), open failure means absent. The fd is always
// closed. Existence probes must ride the raw backend for the same reason
// the reads do: libc access() is a PLT symbol a hook engine can blind.
bool exists(const Io& io, const char* path);

// Production convenience: existence probe via the raw-syscall backend.
inline bool exists(const char* path) { return exists(svc_io, path); }

// Production convenience: sensitive file read via the raw-syscall backend.
inline bool read_file(const char* path, std::string* out,
                      size_t cap = kDefaultReadCap) {
    return read_file(svc_io, path, out, cap);
}

// fgets replacement over an in-memory buffer: the converted call sites used
// stdio line streaming, so the read side ships the same iteration shape. Each
// next() strips the '\n' terminator; a final unterminated line still yields;
// empty lines yield as empty strings (the old code saw bare "\n" and failed
// its sscanf — same net effect, without the special case). Unlike fgets there
// is no line-length truncation: a 4096-byte stack buffer used to silently cut
// long maps lines; the cursor hands the site the whole line. [buf] must outlive
// the cursor (it is referenced, not copied).
class LineCursor {
public:
    explicit LineCursor(const std::string& buf) : buf_(buf), pos_(0) {}

    bool next(std::string* line) {
        if (pos_ >= buf_.size()) return false;
        const size_t eol = buf_.find('\n', pos_);
        if (eol == std::string::npos) {
            line->assign(buf_, pos_, buf_.size() - pos_);
            pos_ = buf_.size();
        } else {
            line->assign(buf_, pos_, eol - pos_);
            pos_ = eol + 1;
        }
        return true;
    }

private:
    const std::string& buf_;
    size_t pos_;
};

}  // namespace dicore::svc
