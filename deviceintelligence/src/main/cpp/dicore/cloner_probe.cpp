// cloner_probe.cpp — implementation of the F13 readers.
//
// Each of the three readers is a tiny line-stream parser over a
// /proc/self/* file. We deliberately avoid:
//   - libc stdio (FILE*, fgets): would re-enter libc, which is
//     exactly what a Frida/Riru/Magisk-style attacker can hook.
//   - Android NDK helpers (__system_property_get, base::ReadFile):
//     same reason, plus they pull in extra dependencies we don't
//     want in libdicore.so.
//   - heap allocation: each reader uses a fixed-size on-stack
//     buffer, so a probe can never OOM the host process.
//
// The parsing is intentionally tolerant: any line we don't
// recognise is silently skipped, and any read error short-circuits
// the reader to "no signal" (return 0 / -1). The Kotlin facade
// treats "no signal" as "real device", so a parse bug here can
// only cause a false negative, never a false positive.

#include "cloner_probe.h"

#include "log.h"
#include "syscalls.h"

#include <fcntl.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace dicore::cloner {

namespace {

// On-stack scratch for one /proc file's contents. /proc/self/maps
// can be hundreds of KB on a complex app; we read it incrementally
// in 4 KB chunks rather than slurping it all in.
constexpr size_t kChunkSize = 4096;

// Maximum length of a single line we'll process. /proc/self/maps
// lines top out around 200 bytes (path + perms + offsets). Mountinfo
// lines can hit ~512 bytes on devices with deep storage paths.
constexpr size_t kLineBufSize = 1024;

// Process [file_path] line-by-line through [callback]. Callback
// receives a NUL-terminated string (no trailing newline) and returns
// `true` to keep going, `false` to stop. Returns `true` on full
// traversal (including early stop), `false` on any read error.
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
            // else: line longer than buffer; truncate silently
            // (the callback only cares about path-shaped suffixes
            // and we'd rather lose precision than emit garbage).
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
bool ends_with(const char* s, size_t s_len, const char* suffix) {
    size_t suffix_len = std::strlen(suffix);
    if (s_len < suffix_len) return false;
    return std::memcmp(s + s_len - suffix_len, suffix, suffix_len) == 0;
}

// Returns pointer to the last whitespace-delimited token in [s], or
// nullptr if [s] is empty. The maps line format puts the pathname as
// the trailing whitespace-delimited field, so this picks it out.
const char* last_token(const char* s, size_t s_len) {
    if (s_len == 0) return nullptr;
    // Walk backwards past any trailing whitespace.
    ssize_t i = static_cast<ssize_t>(s_len) - 1;
    while (i >= 0 && (s[i] == ' ' || s[i] == '\t')) --i;
    if (i < 0) return nullptr;
    // Walk backwards to the next whitespace.
    while (i >= 0 && s[i] != ' ' && s[i] != '\t') --i;
    return s + (i + 1);
}

// Copies [src] into [dst] of size [dst_size], NUL-terminating.
// Returns the number of bytes written (excluding NUL), capped at
// dst_size - 1.
size_t copy_to(char* dst, size_t dst_size, const char* src) {
    if (dst_size == 0) return 0;
    size_t src_len = std::strlen(src);
    size_t n = src_len < dst_size - 1 ? src_len : dst_size - 1;
    std::memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

// Crude package-name detector: returns the first substring inside
// [path] that LOOKS like an Android package name (e.g. "com.foo.bar")
// and isn't equal to [exclude]. We use it to spot the cloner's own
// package name leaking into the source path of a bind mount.
//
// Out-of-scope: anything that isn't of the form "abc.def(.ghi)*". A
// determined attacker could pick a bind-mount source path that doesn't
// contain a package-shaped string, in which case this returns false
// and the caller's signal silently drops. That's fine — the APK_PATH
// signal is the primary guard.
bool find_other_package_in_path(const char* path,
                                const char* exclude,
                                char* out, size_t out_size) {
    const char* p = path;
    while (*p) {
        // Find a candidate: alphanumeric + dot, length >= 5, with
        // at least one '.' that isn't first/last.
        while (*p && !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) ++p;
        if (!*p) break;
        const char* start = p;
        bool saw_dot = false;
        while (*p &&
               ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                (*p >= '0' && *p <= '9') || *p == '.' || *p == '_')) {
            if (*p == '.') saw_dot = true;
            ++p;
        }
        size_t len = static_cast<size_t>(p - start);
        if (saw_dot && len >= 5 && start[0] != '.' && *(p - 1) != '.') {
            // It's package-shaped. Check we're not matching `exclude`.
            size_t exclude_len = std::strlen(exclude);
            bool same = (len == exclude_len) &&
                        std::memcmp(start, exclude, len) == 0;
            if (!same) {
                size_t n = len < out_size - 1 ? len : out_size - 1;
                std::memcpy(out, start, n);
                out[n] = '\0';
                return true;
            }
        }
    }
    return false;
}

}  // namespace

int read_apk_path_from_maps(char* out, size_t out_size) {
    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    int written = 0;

    bool ok = stream_lines("/proc/self/maps",
        [&](const char* line, size_t line_len) -> bool {
            if (!ends_with(line, line_len, "/base.apk")) return true;
            const char* path = last_token(line, line_len);
            if (!path || path[0] != '/') return true;
            written = static_cast<int>(copy_to(out, out_size, path));
            return false; // stop streaming
        });

    if (!ok) return -1;
    return written;
}

// True if [path] contains [pkg] as a `/`- or `-`-bounded component.
// Mirrors the Kotlin `pathContainsPackageComponent` helper so both
// sides agree on what "this path belongs to package X" means.
static bool path_has_pkg_component(const char* path, const char* pkg) {
    size_t pkg_len = std::strlen(pkg);
    if (pkg_len == 0) return false;
    const char* p = path;
    while ((p = std::strstr(p, pkg)) != nullptr) {
        bool left_ok = (p == path) || (*(p - 1) == '/');
        char right = *(p + pkg_len);
        bool right_ok = (right == '/') || (right == '-') || (right == '\0');
        if (left_ok && right_ok) return true;
        p += pkg_len;
    }
    return false;
}

// True if [s] ends with ".apk" — wildcard match for base.apk,
// split_xx.apk, etc.
static bool ends_with_dot_apk(const char* s, size_t s_len) {
    return ends_with(s, s_len, ".apk");
}

int find_foreign_apk_in_maps(const char* my_package,
                             char* out, size_t out_size) {
    if (!my_package || !out || out_size == 0) return -1;
    out[0] = '\0';
    int written = 0;

    bool ok = stream_lines("/proc/self/maps",
        [&](const char* line, size_t line_len) -> bool {
            if (!ends_with_dot_apk(line, line_len)) return true;
            const char* path = last_token(line, line_len);
            if (!path || path[0] != '/') return true;

            // Skip system / framework apks — only application apks
            // under /data/app or /data/user can possibly have a
            // package-name component to compare against.
            if (std::strncmp(path, "/data/", 6) != 0) return true;

            if (!path_has_pkg_component(path, my_package)) {
                written = static_cast<int>(copy_to(out, out_size, path));
                return false; // stop on first foreign hit
            }
            return true;
        });

    if (!ok) return -1;
    return written;
}

int find_suspicious_mount(const char* package_name,
                          char* out, size_t out_size) {
    if (!package_name || !out || out_size == 0) return -1;
    out[0] = '\0';
    int written = 0;

    // Build "/<package_name>" once — the suffix we look for on
    // mount-points.
    char pkg_suffix[256];
    if (std::strlen(package_name) + 2 > sizeof(pkg_suffix)) {
        // Pathologically long package; skip the check.
        return 0;
    }
    pkg_suffix[0] = '/';
    std::strcpy(pkg_suffix + 1, package_name);

    bool ok = stream_lines("/proc/self/mountinfo",
        [&](const char* line, size_t line_len) -> bool {
            // mountinfo line format (whitespace-separated):
            //   id parent major:minor source mount-point opts1
            //     - fstype source-dev opts2
            //
            // We need columns 4 (source), 5 (mount-point), and the
            // first token after the standalone " - " marker (fstype).
            //
            // Tokenise into a small stack array.
            constexpr size_t kMaxCols = 16;
            const char* cols[kMaxCols];
            size_t col_lens[kMaxCols];
            size_t col_count = 0;

            // Mutate a local copy of the line so we can NUL-terminate
            // tokens in place.
            char buf[kLineBufSize];
            if (line_len >= sizeof(buf)) return true; // skip oversize
            std::memcpy(buf, line, line_len + 1);

            char* p = buf;
            while (*p && col_count < kMaxCols) {
                while (*p == ' ' || *p == '\t') *p++ = '\0';
                if (!*p) break;
                cols[col_count] = p;
                while (*p && *p != ' ' && *p != '\t') ++p;
                col_lens[col_count] = static_cast<size_t>(p - cols[col_count]);
                ++col_count;
            }
            if (col_count < 7) return true;

            // Find the standalone "-" separator.
            size_t dash_idx = SIZE_MAX;
            for (size_t i = 6; i < col_count; ++i) {
                if (col_lens[i] == 1 && cols[i][0] == '-') {
                    dash_idx = i;
                    break;
                }
            }
            if (dash_idx == SIZE_MAX || dash_idx + 2 >= col_count) return true;

            const char* source_in_fs = cols[3];
            const char* mount_point = cols[4];
            size_t mount_point_len = col_lens[4];
            const char* fstype = cols[dash_idx + 1];

            // Test 1: mount-point ends with "/<pkg>" AND fstype is tmpfs.
            // Real Android never tmpfs-mounts an app data dir; cloners
            // using filesystem virtualisation routinely do.
            bool ends_with_pkg =
                ends_with(mount_point, mount_point_len, pkg_suffix);
            if (ends_with_pkg && std::strcmp(fstype, "tmpfs") == 0) {
                int n = std::snprintf(out, out_size,
                                      "fstype=tmpfs|mount=%s|source=%s",
                                      mount_point, source_in_fs);
                written = (n > 0) ? n : 0;
                return false; // stop on first hit
            }

            // Test 2: mount-point ends with "/<pkg>" AND source path
            // mentions a *different* package name. This catches cloners
            // that bind-mount their own per-app data dir over ours.
            if (ends_with_pkg) {
                char other[128];
                if (find_other_package_in_path(source_in_fs, package_name,
                                               other, sizeof(other))) {
                    int n = std::snprintf(out, out_size,
                                          "fstype=%s|mount=%s|source=%s|host_pkg=%s",
                                          fstype, mount_point, source_in_fs, other);
                    written = (n > 0) ? n : 0;
                    return false;
                }
            }
            return true;
        });

    if (!ok) return -1;
    return written;
}

int list_data_dir_owners(char* out, size_t out_size) {
    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    size_t written = 0;

    // Bounded list of unique pkg names; we never hand-back more than
    // this many. 32 covers any realistic mount layout (a typical
    // device has 4-5 mounts per app: data, user_de, profiles cur,
    // profiles ref).
    constexpr size_t kMaxOwners = 32;
    constexpr size_t kMaxPkgLen = 96;
    char owners[kMaxOwners][kMaxPkgLen];
    size_t owner_count = 0;

    auto already_seen = [&](const char* p, size_t len) -> bool {
        for (size_t i = 0; i < owner_count; ++i) {
            if (std::strlen(owners[i]) == len &&
                std::memcmp(owners[i], p, len) == 0) {
                return true;
            }
        }
        return false;
    };

    auto try_capture_owner_from_mount = [&](const char* mount_point) {
        if (owner_count >= kMaxOwners) return;
        // Try each prefix in turn; whatever follows the prefix up
        // to the next '/' (or end) is the package component.
        static const char* const kPrefixes[] = {
            "/data/data/",
            "/data/user/0/",
            "/data/user_de/0/",
            "/data/misc/profiles/cur/0/",
            "/data/misc/profiles/ref/",
        };
        for (const char* prefix : kPrefixes) {
            size_t prefix_len = std::strlen(prefix);
            if (std::strncmp(mount_point, prefix, prefix_len) != 0) continue;
            const char* pkg_start = mount_point + prefix_len;
            const char* slash = std::strchr(pkg_start, '/');
            size_t pkg_len = slash ? static_cast<size_t>(slash - pkg_start)
                                   : std::strlen(pkg_start);
            if (pkg_len == 0 || pkg_len >= kMaxPkgLen) return;
            // Must look package-shaped: at least one '.' in there.
            bool saw_dot = false;
            for (size_t i = 0; i < pkg_len; ++i) {
                if (pkg_start[i] == '.') { saw_dot = true; break; }
            }
            if (!saw_dot) return;
            if (already_seen(pkg_start, pkg_len)) return;
            std::memcpy(owners[owner_count], pkg_start, pkg_len);
            owners[owner_count][pkg_len] = '\0';
            ++owner_count;
            return;
        }
    };

    bool ok = stream_lines("/proc/self/mountinfo",
        [&](const char* line, size_t line_len) -> bool {
            // We only need column 5 (mount-point). Tokenise lazily.
            char buf[kLineBufSize];
            if (line_len >= sizeof(buf)) return true;
            std::memcpy(buf, line, line_len + 1);

            char* p = buf;
            int col = 0;
            char* mount_point = nullptr;
            while (*p) {
                while (*p == ' ' || *p == '\t') *p++ = '\0';
                if (!*p) break;
                if (col == 4) { mount_point = p; break; }
                ++col;
                while (*p && *p != ' ' && *p != '\t') ++p;
            }
            if (mount_point) {
                // Re-NUL at next whitespace so it's a clean C string.
                char* q = mount_point;
                while (*q && *q != ' ' && *q != '\t') ++q;
                *q = '\0';
                try_capture_owner_from_mount(mount_point);
            }
            // Always continue — we need every line to build the set.
            return owner_count < kMaxOwners;
        });

    if (!ok) return -1;
    if (owner_count == 0) return 0;

    for (size_t i = 0; i < owner_count; ++i) {
        size_t pkg_len = std::strlen(owners[i]);
        // Need room for "|" between entries (except first).
        size_t need = pkg_len + (i == 0 ? 0 : 1);
        if (written + need + 1 > out_size) break;
        if (i > 0) out[written++] = '|';
        std::memcpy(out + written, owners[i], pkg_len);
        written += pkg_len;
    }
    out[written] = '\0';
    return static_cast<int>(written);
}

int read_kernel_uid_from_status() {
    int parsed_uid = -1;

    bool ok = stream_lines("/proc/self/status",
        [&](const char* line, size_t line_len) -> bool {
            // Looking for: "Uid:\t<real>\t<eff>\t<saved>\t<fs>"
            constexpr const char* kPrefix = "Uid:";
            constexpr size_t kPrefixLen = 4;
            if (line_len < kPrefixLen + 1) return true;
            if (std::memcmp(line, kPrefix, kPrefixLen) != 0) return true;
            // Skip the prefix and any whitespace.
            const char* p = line + kPrefixLen;
            while (*p == ' ' || *p == '\t') ++p;
            if (!*p || !(*p >= '0' && *p <= '9')) return true;
            // strtol via inline loop (avoid pulling libc strtol in
            // case it's hooked; status's number format is trivial).
            int v = 0;
            while (*p >= '0' && *p <= '9') {
                v = v * 10 + (*p - '0');
                ++p;
            }
            parsed_uid = v;
            return false; // stop streaming
        });

    if (!ok) return -1;
    return parsed_uid;
}

int collect_mount_fstypes(char* out, size_t out_size, int* out_count) {
    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    size_t written = 0;
    int total = 0;

    // Deduplicated list of unique fstype strings (e.g. "ext4", "overlay").
    // Max 16 distinct types, each <= 31 chars.
    constexpr size_t kMaxTypes = 16;
    constexpr size_t kMaxTypeLen = 32;
    char types[kMaxTypes][kMaxTypeLen];
    size_t type_count = 0;

    auto already_seen = [&](const char* t, size_t tlen) -> bool {
        for (size_t i = 0; i < type_count; ++i) {
            if (std::strlen(types[i]) == tlen &&
                std::memcmp(types[i], t, tlen) == 0) return true;
        }
        return false;
    };

    bool ok = stream_lines("/proc/self/mountinfo",
        [&](const char* line, size_t line_len) -> bool {
            // mountinfo line format (space-separated fields):
            //   id parent major:minor root mountpoint opts1 ... - fstype source opts2
            // We only need the fstype which is the first token after " - ".
            char buf[kLineBufSize];
            if (line_len >= sizeof(buf)) return true;
            std::memcpy(buf, line, line_len + 1);

            char* dash = std::strstr(buf, " - ");
            if (!dash) return true;
            total++;

            const char* fstype = dash + 3;
            while (*fstype == ' ' || *fstype == '\t') ++fstype;
            if (!*fstype) return true;

            const char* fend = fstype;
            while (*fend && *fend != ' ' && *fend != '\t') ++fend;
            size_t flen = static_cast<size_t>(fend - fstype);
            if (flen == 0 || flen >= kMaxTypeLen) return true;

            if (!already_seen(fstype, flen) && type_count < kMaxTypes) {
                std::memcpy(types[type_count], fstype, flen);
                types[type_count][flen] = '\0';
                ++type_count;
            }
            return true;
        });

    if (!ok) return -1;
    if (out_count) *out_count = total;

    for (size_t i = 0; i < type_count; ++i) {
        size_t tlen = std::strlen(types[i]);
        size_t need = tlen + (i == 0 ? 0 : 1);
        if (written + need + 1 > out_size) break;
        if (i > 0) out[written++] = ',';
        std::memcpy(out + written, types[i], tlen);
        written += tlen;
    }
    out[written] = '\0';
    return static_cast<int>(written);
}

}  // namespace dicore::cloner
