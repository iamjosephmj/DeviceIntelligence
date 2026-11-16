// cloner_proc.h — shared /proc line-stream reader + parse helpers for the F13
// cloner signals. Each signal TU (signal_apk_path / signal_mount / signal_uid)
// builds on stream_lines() here rather than re-implementing the chunked reader.
//
// We deliberately avoid libc stdio (FILE*/fgets) and NDK helpers: both re-enter
// libc, which is exactly what a Frida/Riru/Magisk-style attacker hooks. Every
// reader uses fixed on-stack buffers, so a probe can never OOM the host.

#ifndef DICORE_CLONER_PROC_H_
#define DICORE_CLONER_PROC_H_

#include "dicore/platform/log.h"
#include "dicore/platform/syscalls.h"

#include <fcntl.h>
#include <cstddef>

namespace dicore::cloner::detail {

// On-stack scratch sizes. /proc/self/maps is read incrementally in 4 KB chunks;
// a single mountinfo line can hit ~512 bytes on deep storage paths.
constexpr size_t kChunkSize = 4096;
constexpr size_t kLineBufSize = 1024;

// Process [file_path] line-by-line through [callback]. Callback receives a
// NUL-terminated line (no trailing newline) + its length and returns `true` to
// keep going, `false` to stop. Returns `true` on full traversal (incl. early
// stop), `false` on any read error. Template so the callback inlines with no
// std::function heap/indirection.
template <typename F>
bool stream_lines(const char* file_path, F&& callback) {
    int err = 0;
    int fd = sys::raw_openat(AT_FDCWD, file_path, O_RDONLY, 0, &err);
    if (fd < 0) {
        RLOGW("cloner: openat(%s) failed errno=%d", file_path, err);
        return false;
    }

    char chunk[kChunkSize];
    char line[kLineBufSize];
    size_t line_len = 0;

    while (true) {
        ssize_t n = sys::raw_read_full(fd, chunk, kChunkSize, &err);
        if (n < 0) {
            RLOGW("cloner: read(%s) errno=%d", file_path, err);
            sys::raw_close(fd);
            return false;
        }
        if (n == 0) break; // EOF

        for (ssize_t i = 0; i < n; ++i) {
            char c = chunk[i];
            if (c == '\n') {
                line[line_len] = '\0';
                if (!callback(line, line_len)) {
                    sys::raw_close(fd);
                    return true;
                }
                line_len = 0;
            } else if (line_len < kLineBufSize - 1) {
                line[line_len++] = c;
            }
            // else: line longer than buffer; truncate silently.
        }
    }

    // Trailing line without newline (rare for /proc but handle it).
    if (line_len > 0) {
        line[line_len] = '\0';
        callback(line, line_len);
    }

    sys::raw_close(fd);
    return true;
}

// True if [s] ends with [suffix].
bool ends_with(const char* s, size_t s_len, const char* suffix);

// Pointer to the last whitespace-delimited token in [s] (the maps pathname is
// the trailing field), or nullptr if [s] is empty.
const char* last_token(const char* s, size_t s_len);

// Copy [src] into [dst] of size [dst_size], NUL-terminating; returns bytes
// written (excluding NUL), capped at dst_size-1.
size_t copy_to(char* dst, size_t dst_size, const char* src);

// First package-shaped substring ("abc.def(.ghi)*") inside [path] that isn't
// equal to [exclude], written to [out]. Used to spot a cloner's own package name
// leaking into a bind-mount source path.
bool find_other_package_in_path(const char* path, const char* exclude,
                                char* out, size_t out_size);

}  // namespace dicore::cloner::detail

#endif  // DICORE_CLONER_PROC_H_
