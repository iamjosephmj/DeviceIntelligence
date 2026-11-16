// signal_apk_path.cpp — the maps-based cloner signals: which APKs are mmapped in
// our address space. A multi-app launcher's OWN base.apk must also be mapped (its
// host code runs from there), carrying a foreign package name a real install never
// has. See cloner_probe.h for the full rationale.

#include "dicore/detectors/cloner/cloner_probe.h"
#include "dicore/detectors/cloner/proc/cloner_proc.h"

#include <cstring>

namespace dicore::cloner {

using namespace detail;

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

int read_own_apk_path_from_maps(const char* pkg, char* out, size_t out_size) {
    if (!out || out_size == 0 || !pkg || pkg[0] == '\0') return -1;
    out[0] = '\0';
    int written = 0;

    bool ok = stream_lines("/proc/self/maps",
        [&](const char* line, size_t line_len) -> bool {
            if (!ends_with(line, line_len, "/base.apk")) return true;
            const char* path = last_token(line, line_len);
            if (!path || path[0] != '/') return true;
            if (!path_has_pkg_component(path, pkg)) return true;   // someone else's APK
            written = static_cast<int>(copy_to(out, out_size, path));
            return false; // stop streaming
        });

    if (!ok) return -1;
    return written;
}

bool path_has_pkg_component(const char* path, const char* pkg) {
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

namespace {
// True if [s] ends with ".apk" — wildcard for base.apk, split_xx.apk, etc.
bool ends_with_dot_apk(const char* s, size_t s_len) {
    return ends_with(s, s_len, ".apk");
}
}  // namespace

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

            // Skip system / framework apks — only application apks under
            // /data/app or /data/user can have a package-name component.
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

}  // namespace dicore::cloner
