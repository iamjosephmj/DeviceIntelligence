// cloner_proc.cpp — definitions of the shared parse helpers declared in
// cloner_proc.h. (stream_lines is a template and lives entirely in the header.)

#include "dicore/detectors/cloner/proc/cloner_proc.h"

#include <cstring>

namespace dicore::cloner::detail {

bool ends_with(const char* s, size_t s_len, const char* suffix) {
    size_t suffix_len = std::strlen(suffix);
    if (s_len < suffix_len) return false;
    return std::memcmp(s + s_len - suffix_len, suffix, suffix_len) == 0;
}

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

size_t copy_to(char* dst, size_t dst_size, const char* src) {
    if (dst_size == 0) return 0;
    size_t src_len = std::strlen(src);
    size_t n = src_len < dst_size - 1 ? src_len : dst_size - 1;
    std::memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

bool find_other_package_in_path(const char* path, const char* exclude,
                                char* out, size_t out_size) {
    const char* p = path;
    while (*p) {
        // Find a candidate: alpha start, then alphanumeric + dot/underscore,
        // length >= 5, with at least one interior '.'.
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

}  // namespace dicore::cloner::detail
