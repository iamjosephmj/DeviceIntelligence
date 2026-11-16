#include "dicore/detectors/native_integrity/system_libs/load_backing.h"

#include "dicore/detectors/native_integrity/system_libs/proc_backing_parse.h"
#include "dicore/platform/syscalls.h"

#include <android/api-level.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {
namespace {

constexpr size_t kChunk = 4096;
constexpr size_t kLineMax = 1024;  // /proc lines (maps/mountinfo) fit comfortably

// Raw-syscall /proc line reader: calls cb(line, len) per NUL-free line (no trailing
// newline); stops early when cb returns false. No libc stdio (anti-hook).
template <typename F>
void read_proc_lines(const char* path, F&& cb) {
    int err = 0;
    int fd = sys::raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, &err);
    if (fd < 0) return;
    char chunk[kChunk];
    char line[kLineMax] = {};
    size_t line_len = 0;
    bool eof = false;
    for (;;) {
        ssize_t n = sys::raw_read_full(fd, chunk, kChunk, &err);
        if (n < 0) break;          // read error -> do NOT deliver the partial tail
        if (n == 0) { eof = true; break; }
        for (ssize_t i = 0; i < n; ++i) {
            const char c = chunk[i];
            if (c == '\n') {
                if (!cb(line, line_len)) { sys::raw_close(fd); return; }
                line_len = 0;
            } else if (line_len < kLineMax - 1) {
                line[line_len++] = c;
            }
            // else: oversize line truncated (no /proc line we care about is this long)
        }
    }
    if (eof && line_len > 0) cb(line, line_len);
    sys::raw_close(fd);
}

}  // namespace

LibcBackingStatus scan_libc_backing() {
    if (::android_get_device_api_level() < 30) return LibcBackingStatus::kUnavailable;

    // Pass 1 — libc's backing device from /proc/self/maps (HEX dev).
    bool got_libc = false;
    uint32_t libc_maj = 0, libc_min = 0;
    read_proc_lines("/proc/self/maps", [&](const char* l, size_t n) -> bool {
        if (parse_maps_libc_dev(l, n, &libc_maj, &libc_min)) { got_libc = true; return false; }
        return true;
    });
    if (!got_libc) return LibcBackingStatus::kUnavailable;

    // Pass 2 — the /apex/com.android.runtime mount (DECIMAL dev + legitimacy).
    bool got_apex = false;
    ApexMount apex{};
    read_proc_lines("/proc/self/mountinfo", [&](const char* l, size_t n) -> bool {
        if (parse_mountinfo_apex(l, n, &apex)) { got_apex = true; return false; }
        return true;
    });
    if (!got_apex) return LibcBackingStatus::kUnavailable;

    // Signal A — backing-device consistency.
    if (libc_maj != apex.major || libc_min != apex.minor)
        return LibcBackingStatus::kBackingMismatch;

    // Signal B — apex mount legitimacy.
    if (!(apex.ro && apex.fstype_ok && apex.source_devblock))
        return LibcBackingStatus::kApexUntrusted;

    return LibcBackingStatus::kOk;
}

const char* libc_backing_status_name(LibcBackingStatus s) {
    switch (s) {
        case LibcBackingStatus::kOk: return "ok";
        case LibcBackingStatus::kBackingMismatch: return "backing_mismatch";
        case LibcBackingStatus::kApexUntrusted: return "apex_untrusted";
        default: return "unavailable";
    }
}

}  // namespace dicore::native_integrity
