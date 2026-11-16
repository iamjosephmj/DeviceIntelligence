// signal_mount.cpp — the mountinfo-based cloner signals. Real Android never
// tmpfs-mounts an app data dir and never bind-mounts a foreign package over ours;
// cloners using filesystem virtualisation routinely do both. Also enumerates the
// data-dir owners and the set of mounted fstypes for the facade's cross-checks.

#include "dicore/detectors/cloner/cloner_probe.h"
#include "dicore/detectors/cloner/proc/cloner_proc.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace dicore::cloner {

using namespace detail;

int find_suspicious_mount(const char* package_name,
                          char* out, size_t out_size) {
    if (!package_name || !out || out_size == 0) return -1;
    out[0] = '\0';
    int written = 0;

    // Build "/<package_name>" once — the suffix we look for on mount-points.
    char pkg_suffix[256];
    if (std::strlen(package_name) + 2 > sizeof(pkg_suffix)) {
        return 0;  // pathologically long package; skip the check
    }
    pkg_suffix[0] = '/';
    std::strcpy(pkg_suffix + 1, package_name);

    bool ok = stream_lines("/proc/self/mountinfo",
        [&](const char* line, size_t line_len) -> bool {
            // mountinfo line format (whitespace-separated):
            //   id parent major:minor source mount-point opts1 - fstype src opts2
            // We need columns 4 (source), 5 (mount-point), and the first token
            // after the standalone " - " marker (fstype).
            constexpr size_t kMaxCols = 16;
            const char* cols[kMaxCols];
            size_t col_lens[kMaxCols];
            size_t col_count = 0;

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
            bool ends_with_pkg =
                ends_with(mount_point, mount_point_len, pkg_suffix);
            if (ends_with_pkg && std::strcmp(fstype, "tmpfs") == 0) {
                int n = std::snprintf(out, out_size,
                                      "fstype=tmpfs|mount=%s|source=%s",
                                      mount_point, source_in_fs);
                written = (n > 0) ? n : 0;
                return false; // stop on first hit
            }

            // Test 2: mount-point ends with "/<pkg>" AND source path mentions a
            // *different* package name (a cloner bind-mounting its data over ours).
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

    // Bounded list of unique pkg names. 32 covers any realistic mount layout
    // (~4-5 mounts per app: data, user_de, profiles cur, profiles ref).
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
                char* q = mount_point;
                while (*q && *q != ' ' && *q != '\t') ++q;
                *q = '\0';
                try_capture_owner_from_mount(mount_point);
            }
            return owner_count < kMaxOwners;
        });

    if (!ok) return -1;
    if (owner_count == 0) return 0;

    for (size_t i = 0; i < owner_count; ++i) {
        size_t pkg_len = std::strlen(owners[i]);
        size_t need = pkg_len + (i == 0 ? 0 : 1);
        if (written + need + 1 > out_size) break;
        if (i > 0) out[written++] = '|';
        std::memcpy(out + written, owners[i], pkg_len);
        written += pkg_len;
    }
    out[written] = '\0';
    return static_cast<int>(written);
}

int collect_mount_fstypes(char* out, size_t out_size, int* out_count) {
    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    size_t written = 0;
    int total = 0;

    // Deduplicated unique fstype strings (e.g. "ext4", "overlay"). Max 16, <=31 ch.
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
            // fstype is the first token after " - ".
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
