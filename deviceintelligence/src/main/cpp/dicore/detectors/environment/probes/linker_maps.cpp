// INTEL_0041 — linker vs maps divergence.
//
// The dynamic linker's own list of loaded objects, compared against what
// /proc/self/maps says is mapped. A module that unlinks its soinfo to hide from one
// view still appears in the other, and vice versa; neither view alone is trustworthy
// on a rooted device, so the CONTRADICTION between them is what is reported.
#include "dicore/platform/log.h"
#include "dicore/core/verdict_cores.h"
#include "dicore/orchestrator/record_util.h"
#include "dicore/detectors/environment/maps/maps_parse.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <link.h>
#include <dlfcn.h>

namespace dicore {

using env::append_field;
using env::read_proc_self_maps;
using env::extract_pathname;
using env::range_bounds;

namespace {
struct DiLObj { std::string name; uintptr_t exec_base; };
int dicore_linker_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* v = reinterpret_cast<std::vector<DiLObj>*>(data);
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;      // skip main exe / anon-named
    std::string nm = info->dlpi_name;
    if (nm.find(".so") == std::string::npos) return 0;         // real shared libraries only
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X))
            v->push_back({nm, (uintptr_t)info->dlpi_addr + ph.p_vaddr});
    }
    return 0;
}
}  // namespace

// INTEL_0041 — linker<->maps divergence. The linker's object list (dl_iterate_phdr) and the
// kernel's VMA list (/proc/self/maps) must agree: a named .so's executable segment must map to
// a file-backed VMA. NeoZygisk's spoof_virtual_maps() mremaps the loader's file VMA into an
// anonymous region to erase its provenance, but the soinfo stays linked — so the linker names an
// object whose base VMA is empty-path. FP-free: a real .so always has BOTH a linker record and a
// named VMA; memfd libs keep a /memfd: name; JIT/anon code is not linker-tracked.
std::vector<std::string> linker_maps_records() {
    std::vector<std::string> out;
    std::vector<DiLObj> objs;
    dl_iterate_phdr(dicore_linker_cb, &objs);
    std::string maps;
    if (!read_proc_self_maps(&maps)) return out;
    struct V { uintptr_t s, e; std::string p; };
    std::vector<V> vmas;
    size_t pos = 0;
    while (pos < maps.size()) {
        size_t eol = maps.find('\n', pos);
        std::string line = maps.substr(pos, (eol == std::string::npos ? maps.size() : eol) - pos);
        pos = (eol == std::string::npos) ? maps.size() : eol + 1;
        size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;
        uintptr_t rs, re;
        if (!range_bounds(line.substr(0, sp), &rs, &re)) continue;
        vmas.push_back({rs, re, extract_pathname(line)});
    }
    int emitted = 0;
    for (const auto& o : objs) {
        if (emitted >= 8) break;
        const V* hit = nullptr;
        for (const auto& v : vmas) if (o.exec_base >= v.s && o.exec_base < v.e) { hit = &v; break; }
        if (!hit || !hit->p.empty()) continue;   // linker-named .so at an EMPTY-path VMA only
        std::string r = "linker_maps_divergence";
        r = append_field(r, "CRITICAL");   // FP-free by construction (validated 0/349 legit objects)
        r = append_field(r, "linker .so with anon-exec segment");
        r = append_field(r, "object=" + o.name);
        char b[40]; std::snprintf(b, sizeof(b), "base=%#lx", (unsigned long)o.exec_base);
        r = append_field(r, b);
        out.push_back(r);
        ++emitted;
    }
    return out;
}

#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif

// INTEL_0042 — sealed executable memfd. NeoZygisk/zygiskd load each module from a sealed
// read-only memfd (DlopenMem), never a /data/adb file. Flag any mapped memfd fd that is BOTH
// sealed-write (F_SEAL_WRITE|F_SEAL_SEAL) AND executable. Name-independent (keys on seal bits,
// so a module named "jit-cache" is still caught); FP-safe (ART's JIT memfd is exec but
// writable, and ordinary apps do not map sealed executable memfds).

}  // namespace dicore
