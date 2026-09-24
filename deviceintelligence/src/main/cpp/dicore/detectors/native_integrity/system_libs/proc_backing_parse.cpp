#include "dicore/detectors/native_integrity/system_libs/proc_backing_parse.h"

#include <cstring>

namespace dicore::native_integrity {
namespace {

// The i-th whitespace-delimited token of [s,len] as (ptr,len). false if absent.
bool token_at(const char* s, size_t len, size_t idx, const char** tp, size_t* tl) {
    size_t i = 0;
    size_t cur = 0;
    while (i < len) {
        while (i < len && (s[i] == ' ' || s[i] == '\t')) ++i;
        if (i >= len) break;
        const size_t start = i;
        while (i < len && s[i] != ' ' && s[i] != '\t') ++i;
        if (cur == idx) { *tp = s + start; *tl = i - start; return true; }
        ++cur;
    }
    return false;
}

bool token_eq(const char* t, size_t tl, const char* s) {
    return tl == std::strlen(s) && std::memcmp(t, s, tl) == 0;
}

bool ends_with(const char* s, size_t len, const char* suf) {
    const size_t sl = std::strlen(suf);
    return len >= sl && std::memcmp(s + len - sl, suf, sl) == 0;
}

// One base-`base` digit value, or -1 if not a valid digit for that base.
int digit_val(char c, uint32_t base) {
    uint32_t v = 0;
    if (c >= '0' && c <= '9') v = static_cast<uint32_t>(c - '0');
    else if (c >= 'a' && c <= 'f') v = static_cast<uint32_t>(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') v = static_cast<uint32_t>(c - 'A' + 10);
    else return -1;
    return v < base ? static_cast<int>(v) : -1;
}

// Parse a "<maj>:<min>" device token in the given base into *maj/*min.
bool parse_dev(const char* t, size_t tl, uint32_t base, uint32_t* maj, uint32_t* min) {
    size_t c = 0;
    while (c < tl && t[c] != ':') ++c;
    if (c == 0 || c >= tl || c == tl - 1) return false;  // need digits on both sides
    uint32_t a = 0, b = 0;
    for (size_t i = 0; i < c; ++i) { int d = digit_val(t[i], base); if (d < 0) return false; if (a > (0xFFFFFFFFu - static_cast<uint32_t>(d)) / base) return false; a = a * base + static_cast<uint32_t>(d); }
    for (size_t i = c + 1; i < tl; ++i) { int d = digit_val(t[i], base); if (d < 0) return false; if (b > (0xFFFFFFFFu - static_cast<uint32_t>(d)) / base) return false; b = b * base + static_cast<uint32_t>(d); }
    *maj = a; *min = b;
    return true;
}

}  // namespace

bool parse_maps_libc_dev(const char* line, size_t len, uint32_t* major, uint32_t* minor) {
    if (!line || len == 0) return false;
    // Trim a trailing newline / spaces so the suffix check is robust.
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == ' ' || line[len - 1] == '\t')) --len;
    if (!ends_with(line, len, "/libc.so")) return false;   // excludes libc++.so, libcutils.so, ...
    const char* dev = nullptr; size_t dl = 0;
    if (!token_at(line, len, 3, &dev, &dl)) return false;   // field 3 = dev (HEX)
    return parse_dev(dev, dl, 16, major, minor);
}

bool parse_mountinfo_apex(const char* line, size_t len, ApexMount* out) {
    if (!line || len == 0 || !out) return false;
    const char* mp = nullptr; size_t mpl = 0;
    if (!token_at(line, len, 4, &mp, &mpl)) return false;            // field 4 = mountpoint
    if (!token_eq(mp, mpl, "/apex/com.android.runtime")) return false;

    const char* dev = nullptr; size_t dl = 0;
    if (!token_at(line, len, 2, &dev, &dl)) return false;            // field 2 = dev (DECIMAL)
    ApexMount m{};
    if (!parse_dev(dev, dl, 10, &m.major, &m.minor)) return false;

    const char* opt = nullptr; size_t ol = 0;
    if (token_at(line, len, 5, &opt, &ol))                           // field 5 = options
        m.ro = (ol >= 2 && opt[0] == 'r' && opt[1] == 'o' && (ol == 2 || opt[2] == ','));

    // Find the standalone "-" separator (optional tags sit between field 6 and it).
    size_t dash = 0;
    bool have_dash = false;
    for (size_t i = 6; ; ++i) {
        const char* tp = nullptr; size_t tl = 0;
        if (!token_at(line, len, i, &tp, &tl)) break;
        if (tl == 1 && tp[0] == '-') { dash = i; have_dash = true; break; }
    }
    if (!have_dash) return false;

    const char* fst = nullptr; size_t fl = 0;
    const char* src = nullptr; size_t sl = 0;
    if (token_at(line, len, dash + 1, &fst, &fl))
        m.fstype_ok = token_eq(fst, fl, "ext4") || token_eq(fst, fl, "erofs") || token_eq(fst, fl, "f2fs");
    if (token_at(line, len, dash + 2, &src, &sl)) {
        const char* pfx = "/dev/block/";
        const size_t pl = std::strlen(pfx);
        m.source_devblock = sl >= pl && std::memcmp(src, pfx, pl) == 0;
    }
    *out = m;
    return true;
}

}  // namespace dicore::native_integrity
