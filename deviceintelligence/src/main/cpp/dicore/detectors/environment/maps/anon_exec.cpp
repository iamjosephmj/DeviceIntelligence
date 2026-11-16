// anon_exec.cpp
#include "dicore/detectors/environment/maps/anon_exec.hpp"
#include <cinttypes>
#include <cstring>
#include <cstdio>
namespace dicore::anon_exec {
static bool excluded_name(const char* p) {
    if (!p || !*p) return false;
    static const char* skip[] = {"[vdso]", "[vvar]", "[vectors]", "[vsyscall]",
                                 "[uprobes]", "[jit]", "[anon:"};
    for (auto s : skip) if (std::strncmp(p, s, std::strlen(s)) == 0) return true;
    return false;
}
size_t classify(const char* maps_text, Finding* out, size_t cap) {
    if (!maps_text || !out || cap == 0) return 0;
    size_t n = 0;
    const char* ln = maps_text;
    while (*ln && n < cap) {
        const char* eol = std::strchr(ln, '\n');
        size_t len = eol ? (size_t)(eol - ln) : std::strlen(ln);
        char buf[512];
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        std::memcpy(buf, ln, len); buf[len] = 0;
        uint64_t s = 0, e = 0;
        char perms[8] = {0};
        char path[256] = {0};
        // start-end perms offset dev inode [path]  (SCNx64: uint64_t width
        // differs between 32-bit (unsigned long long) and 64-bit ABIs)
        if (std::sscanf(buf, "%" SCNx64 "-%" SCNx64 " %7s %*s %*s %*s %255[^\n]",
                        &s, &e, perms, path) >= 3) {
            bool exec = std::strchr(perms, 'x') != nullptr;
            bool named = path[0] == '/';
            bool memfd = std::strstr(path, "memfd:") != nullptr;
            bool deleted = std::strstr(path, "(deleted)") != nullptr;
            bool excl = excluded_name(path);
            if (exec && !excl && (!named || memfd || deleted)) {
                Finding& f = out[n++];
                f.start = s; f.end = e;
                std::memcpy(f.perms, perms, 4); f.perms[4] = 0;
                f.memfd = memfd;
                std::strncpy(f.path, path, sizeof(f.path) - 1); f.path[sizeof(f.path)-1] = 0;
            }
        }
        if (!eol) break;
        ln = eol + 1;
    }
    return n;
}
}
