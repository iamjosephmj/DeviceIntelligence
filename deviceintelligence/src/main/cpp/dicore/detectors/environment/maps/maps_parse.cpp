// See maps_parse.h.
#include "dicore/detectors/environment/maps/maps_parse.h"

// kFS: the one US(0x1f) record separator the whole tree shares. This file used
// to carry its own duplicate definition of it.
#include "dicore/orchestrator/record_util.h"
#include "dicore/platform/log.h"
#include "dicore/platform/svc_io.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>

namespace dicore {
namespace env {

namespace {
bool is_tok(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}
}  // namespace

bool boundary_match(const std::string& hay, const char* needle) {
    size_t nlen = std::strlen(needle);
    if (nlen == 0) return false;
    for (size_t pos = hay.find(needle); pos != std::string::npos;
         pos = hay.find(needle, pos + 1)) {
        char before = pos == 0 ? '\0' : hay[pos - 1];
        char after = (pos + nlen >= hay.size()) ? '\0' : hay[pos + nlen];
        if (!is_tok(before) && !is_tok(after)) return true;
    }
    return false;
}

// Pathname = everything after the 5th whitespace-delimited field; "" if none.

bool read_proc_self_maps(std::string* out) {
    // B3: raw-syscall read — a libc fopen/fread hook would feed this scan a
    // sanitized maps file and blind every environment signal at once.
    if (!svc::read_file("/proc/self/maps", out)) {
        RLOGW("procSelfMaps: raw read failed");
        return false;
    }
    return true;
}


std::string extract_pathname(const std::string& line) {
    size_t i = 0, fields = 0;
    while (i < line.size() && fields < 5) {
        while (i < line.size() && line[i] != ' ' && line[i] != '\t') i++;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) i++;
        fields++;
    }
    if (i >= line.size()) return "";
    size_t end = line.size();
    while (end > i && (line[end - 1] == '\n' || line[end - 1] == '\r')) end--;
    return line.substr(i, end - i);
}

// Size in bytes of a "START-END" hex address range, or 0 if unparseable.
unsigned long long region_size(const std::string& range) {
    size_t dash = range.find('-');
    if (dash == std::string::npos || dash == 0 || dash + 1 >= range.size()) return 0;
    char* e1 = nullptr; char* e2 = nullptr;
    unsigned long long start = std::strtoull(range.substr(0, dash).c_str(), &e1, 16);
    unsigned long long end = std::strtoull(range.c_str() + dash + 1, &e2, 16);
    if (end <= start) return 0;
    return end - start;
}

std::string append_field(std::string r, const std::string& f) { r += kFS; r += f; return r; }

// Scan /proc/self/maps and append Finding records (US-framed) to [out].
// Executable-code roots that legitimately host native code. Anything mapped
// executable from OUTSIDE these is foreign injected code (provenance signal) —
// name-independent, unlike the kHookFrameworks list. Generous on OEM partitions
// to stay false-positive-free; a bind-mount over /system is caught separately by
// the APK/lib manifest hash, and real modules live under /data/adb.
bool is_legit_code_root(const std::string& p) {
    static const char* roots[] = {
        "/system/", "/system_ext/", "/apex/", "/vendor/", "/vendor_dlkm/",
        "/product/", "/odm/", "/oem/", "/data/app/", "/data/dalvik-cache/",
        "/data/misc/apexdata/",
    };
    for (auto r : roots) if (p.rfind(r, 0) == 0) return true;
    return p == "[vdso]";
}
// Legitimate ART JIT / dalvik executable regions (ashmem/memfd/anon) — never foreign.
//
// Two rules, deliberately different in shape:
//
//  1. Inside the two containers ART maps its code cache from — `/dev/ashmem/` and
//     `/memfd:` — ANY region whose label names "jit" is the JIT cache. Matching
//     exact names here is what broke: the list said "jit-cache", ART shipped
//     "jit-zygote-cache" (which does NOT contain "jit-cache"), and every clean
//     Android 11 Samsung reported its own zygote JIT cache as injected code.
//     A container-scoped rule survives the next rename; an exact-name list does
//     not, and its failure mode is a false positive on every device.
//
//  2. Outside those containers, match the JIT-specific labels only. A bare
//     "jit" substring must NOT exempt e.g. `/data/local/tmp/libjit.so`, and a
//     bare "dalvik" must not exempt `[anon:dalvik-DEX data]` — the mapping that
//     backs a ByteBuffer-loaded dex, and precisely the thing an injected
//     in-memory dex leaves behind. Widening a whitelist by substring is how a
//     detector goes quietly blind: nothing fails, the region simply stops being
//     considered.
//
// Note what this is NOT: the exemption is by NAME, so a hostile region named
// `jit-*` inside one of those containers is exempted too. That is unchanged by
// the container rule — `jit-cache` was equally spoofable. Name-independent
// confirmation is the RWX hook-pool check (do the stubs branch into real code?),
// which is what actually separates a hook from a cache.
bool jit_container(const std::string& p) {
    return p.rfind("/dev/ashmem/", 0) == 0 || p.rfind("/memfd:", 0) == 0;
}
bool jit_anon(const std::string& p) {
    // A file-backed path is exempt ONLY from inside a JIT container. Otherwise a
    // dropped library could buy immunity by choosing its filename:
    // `/data/local/tmp/jit-cache-hook.so` used to match the name list and escape
    // the foreign-code signal entirely.
    if (!p.empty() && p[0] == '/') {
        return jit_container(p) && p.find("jit") != std::string::npos;
    }
    // Anonymous labels (`[anon:...]`, `[anon_shmem:...]`) carry no path, so the
    // JIT-specific names are all there is to go on.
    return p.find("jit-cache") != std::string::npos ||
           p.find("dalvik-jit") != std::string::npos ||
           p.find("art-jit") != std::string::npos;
}
bool range_bounds(const std::string& range, uintptr_t* s, uintptr_t* e) {
    size_t dash = range.find('-');
    if (dash == std::string::npos) return false;
    *s = (uintptr_t) strtoull(range.substr(0, dash).c_str(), nullptr, 16);
    *e = (uintptr_t) strtoull(range.substr(dash + 1).c_str(), nullptr, 16);
    return *e > *s;
}
// Our own library's load path + a code address, so the detector never flags ITSELF
// as injected (libdicore may be mapped from a non-/data/app path, e.g. memfd).

}  // namespace env
}  // namespace dicore
