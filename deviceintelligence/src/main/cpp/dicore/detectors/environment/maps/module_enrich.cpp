// See module_enrich.h. (pvr<> is defined there — it is a template.)
#include "dicore/detectors/environment/maps/module_enrich.h"
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
#include <map>
#include <unistd.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <link.h>

namespace dicore {
namespace env {

std::string self_lib_path() {
    Dl_info info;
    if (dladdr((void*)&range_bounds, &info) && info.dli_fname && info.dli_fname[0])
        return info.dli_fname;
    return "";
}

// Signal C — ENRICHMENT (not a detection verdict): describe a foreign module by
// reading its MAPPED image (dl_iterate_phdr): module_id/soname + DT_NEEDED, and a hint
// if it links a dedicated hooking library. FAIL-OPEN and crash-safe: DT_STRTAB is
// validated to lie within the module's own mapped span, sonames are read via bounded
// process_vm_readv (never a raw deref), and matching is exact-basename (no strstr). Any
// doubt -> omit the detail. This annotates the INTEL_0035 finding; it never condemns on
// its own, so a benign injected module is described, not falsely flagged.
bool is_hook_soname(const std::string& so) {
    static const char* h[] = {"libdobby.so","libwhale.so","libyahfa.so","liblsplant.so",
        "libsubstrate.so","libshadowhook.so","libbytehook.so","libxhook.so","libsandhook.so",
        "libpine.so","libfrida-gadget.so","libfrida.so"};
    for (auto x : h) if (so == x) return true;
    return false;
}
std::string safe_read_soname(uintptr_t straddr, size_t off, size_t strsz) {
    if (off >= strsz) return "";
    size_t want = strsz - off; if (want > 96) want = 96;
    char buf[96];
    struct iovec lo{buf, want};
    struct iovec ro{reinterpret_cast<void*>(straddr + off), want};
    ssize_t n = process_vm_readv(getpid(), &lo, 1, &ro, 1, 0);
    if (n <= 0) return "";
    size_t k = 0; while (k < (size_t)n && buf[k]) ++k;   // NUL within the bounded read
    if (k == 0 || k >= (size_t)n) return "";
    return std::string(buf, k);
}
// Safe typed read of our own memory: EFAULT (returns false) instead of SIGSEGV.
// Enrichment: parse the foreign module's ELF from its MAPPED BASE (from /proc/self/maps),
// via bounded process_vm_readv only. Returns "needed=...[<FS>links_hook_lib=...]" or "".
// Fail-open at every step: any bad/absent structure -> "" (no detail), never a crash.
std::string enrich_from_base(uintptr_t base) {
    ElfW(Ehdr) eh;
    if (!pvr(base, &eh)) return "";
    if (std::memcmp(eh.e_ident, "\177ELF", 4) != 0) return "";
    if (eh.e_phentsize != sizeof(ElfW(Phdr)) || eh.e_phnum == 0 || eh.e_phnum > 64) return "";
    uintptr_t dyn_addr = 0, lo = UINTPTR_MAX, hi = 0;
    for (int i = 0; i < eh.e_phnum; ++i) {
        ElfW(Phdr) ph;
        if (!pvr(base + eh.e_phoff + (size_t)i * sizeof(ph), &ph)) return "";
        if (ph.p_type == PT_LOAD) {
            uintptr_t s0 = base + ph.p_vaddr;
            if (s0 < lo) lo = s0;
            if (s0 + ph.p_memsz > hi) hi = s0 + ph.p_memsz;
        } else if (ph.p_type == PT_DYNAMIC) {
            dyn_addr = base + ph.p_vaddr;
        }
    }
    if (!dyn_addr || hi <= lo) return "";
    uintptr_t straddr = 0; size_t strsz = 0;
    for (int i = 0; i < 4096; ++i) {
        ElfW(Dyn) d;
        if (!pvr(dyn_addr + (size_t)i * sizeof(d), &d) || d.d_tag == DT_NULL) break;
        if (d.d_tag == DT_STRTAB) {
            uintptr_t a = (uintptr_t)d.d_un.d_ptr;
            if (a < base) a += base;
            straddr = a;
        } else if (d.d_tag == DT_STRSZ) {
            strsz = (size_t)d.d_un.d_val;
        }
    }
    if (!straddr || strsz == 0 || strsz > (1u << 20) || straddr < lo || straddr + strsz > hi) return "";
    std::string needed, hook; int cnt = 0;
    for (int i = 0; i < 4096; ++i) {
        ElfW(Dyn) d;
        if (!pvr(dyn_addr + (size_t)i * sizeof(d), &d) || d.d_tag == DT_NULL) break;
        if (d.d_tag != DT_NEEDED) continue;
        std::string so = safe_read_soname(straddr, (size_t)d.d_un.d_val, strsz);
        if (so.empty()) continue;
        if (++cnt > 24) break;
        if (needed.size() < 400) { if (!needed.empty()) needed += ","; needed += so; }
        if (hook.empty() && is_hook_soname(so)) hook = so;
    }
    std::string det;
    if (!needed.empty()) det = "needed=" + needed;
    if (!hook.empty()) { if (!det.empty()) det += kFS; det += "links_hook_lib=" + hook; }
    return det;
}


#if defined(__LP64__)
#  define DICORE_R_SYM(i) ((i) >> 32)
#else
#  define DICORE_R_SYM(i) ((i) >> 8)
#endif

// The Magisk/KSU/Zygisk module id, from a /data/adb/modules/<id>/ path ("" if not one).
std::string module_id_from_path(const std::string& pth) {
    size_t mp = pth.find("/data/adb/modules/");
    if (mp == std::string::npos) return "";
    size_t ms = mp + 18, me = pth.find('/', ms);
    return (me != std::string::npos && me > ms) ? pth.substr(ms, me - ms) : "";
}

// Which imported symbol does the GOT slot at [slot_vaddr] (vaddr, relative to base)
// correspond to? Parse the VICTIM lib's relocations (.rela.plt/.rela.dyn) from its
// mapped ELF; match r_offset == slot_vaddr; resolve the symbol name. All via bounded
// pvr reads. "" if not resolvable (fail-open).
std::string resolve_reloc_symbol(uintptr_t base, uintptr_t slot_vaddr) {
    ElfW(Ehdr) eh;
    if (!pvr(base, &eh) || std::memcmp(eh.e_ident, "\177ELF", 4) != 0) return "";
    if (eh.e_phentsize != sizeof(ElfW(Phdr)) || eh.e_phnum == 0 || eh.e_phnum > 64) return "";
    uintptr_t dyn = 0;
    for (int i = 0; i < eh.e_phnum; ++i) {
        ElfW(Phdr) ph;
        if (!pvr(base + eh.e_phoff + (size_t)i * sizeof(ph), &ph)) return "";
        if (ph.p_type == PT_DYNAMIC) { dyn = base + ph.p_vaddr; break; }
    }
    if (!dyn) return "";
    uintptr_t jmprel = 0, rela = 0, symtab = 0, strtab = 0;
    size_t pltsz = 0, relasz = 0, strsz = 0;
    for (int i = 0; i < 8192; ++i) {
        ElfW(Dyn) d;
        if (!pvr(dyn + (size_t)i * sizeof(d), &d) || d.d_tag == DT_NULL) break;
        uintptr_t a = (uintptr_t)d.d_un.d_ptr; if (a && a < base) a += base;
        switch (d.d_tag) {
            case DT_JMPREL:   jmprel = a; break;
            case DT_PLTRELSZ: pltsz  = (size_t)d.d_un.d_val; break;
            case DT_RELA:     rela   = a; break;
            case DT_RELASZ:   relasz = (size_t)d.d_un.d_val; break;
            case DT_SYMTAB:   symtab = a; break;
            case DT_STRTAB:   strtab = a; break;
            case DT_STRSZ:    strsz  = (size_t)d.d_un.d_val; break;
        }
    }
    if (!symtab || !strtab || strsz == 0 || strsz > (1u << 20)) return "";
    for (int pass = 0; pass < 2; ++pass) {
        uintptr_t tab = pass ? rela : jmprel;
        size_t sz     = pass ? relasz : pltsz;
        if (!tab || sz == 0 || sz > (16u << 20)) continue;
        size_t cnt = sz / sizeof(ElfW(Rela)); if (cnt > 65536) cnt = 65536;
        for (size_t j = 0; j < cnt; ++j) {
            ElfW(Rela) rl;
            if (!pvr(tab + j * sizeof(ElfW(Rela)), &rl)) break;
            if ((uintptr_t)rl.r_offset != slot_vaddr) continue;
            size_t si = DICORE_R_SYM(rl.r_info);
            if (si == 0 || si > (1u << 22)) return "";
            ElfW(Sym) sym;
            if (!pvr(symtab + si * sizeof(ElfW(Sym)), &sym)) return "";
            return safe_read_soname(strtab, sym.st_name, strsz);   // bounded string read
        }
    }
    return "";
}

// A pointer landed in an [anon]/memfd executable region — is that a hook TRAMPOLINE?
// It is iff the region itself references (contains a pointer into) a file-backed foreign
// module. Legit anon/JIT code never points into /data/adb, so requiring that reference
// keeps this false-positive-free. Returns the referenced module id, or "".

}  // namespace env
}  // namespace dicore
