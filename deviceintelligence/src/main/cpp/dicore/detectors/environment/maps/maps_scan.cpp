// See maps_scan.h.
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
#include "dicore/detectors/environment/maps/maps_scan.h"
#include "dicore/detectors/environment/maps/module_enrich.h"
#include "dicore/detectors/environment/maps/trampoline.h"
#include "dicore/detectors/native_integrity/system_libs/libc_verify.h"

namespace dicore {
namespace env {

namespace {

struct HookFw { const char* canonical; const char* sigs[4]; };
// Mirrors MapsParser.HOOK_FRAMEWORK_SIGNATURES (kept narrow — every entry is a
// framework whose mere presence is a meaningful tampering signal).
const HookFw kHookFrameworks[] = {
    {"frida",         {"frida-agent", "frida-gadget", "gum-js-loop", nullptr}},
    {"substrate",     {"libsubstrate", "cydiasubstrate", nullptr, nullptr}},
    {"xposed",        {"libxposed", "XposedBridge.jar", nullptr, nullptr}},
    {"lsposed",       {"LSPosed", "lspd_", nullptr, nullptr}},
    {"riru",          {"libriru", nullptr, nullptr, nullptr}},
    {"zygisk",        {"libzygisk", nullptr, nullptr, nullptr}},
    {"taichi",        {"libtaichi", nullptr, nullptr, nullptr}},
    {"dobby",         {"libdobby", "dobby_bridge", nullptr, nullptr}},
    {"whale",         {"libwhale", nullptr, nullptr, nullptr}},
    {"yahfa",         {"libyahfa", nullptr, nullptr, nullptr}},
    {"fasthook",      {"libfasthook", nullptr, nullptr, nullptr}},
    {"il2cpp_dumper", {"libil2cppdumper", "zygisk-il2cpp", nullptr, nullptr}},
};

constexpr int kRwxRegionLimit = 8;
constexpr unsigned long long kFridaMemfdJitMinSize = 8ULL * 1024 * 1024;
}  // namespace

void scan_runtime_maps(std::vector<std::string>& out) {
    std::string maps;
    if (!read_proc_self_maps(&maps)) return;

    const std::string g_self_path = self_lib_path();
    std::vector<std::string> frameworks;   // distinct, first-seen order
    std::vector<std::string> rwx_regions;
    std::vector<std::string> memfd_regions;
    int rwx_overflow = 0;
    std::vector<std::pair<uintptr_t,uintptr_t>> foreign_ranges;   // foreign exec ranges (provenance)
    std::vector<std::string> foreign_paths;                        // distinct foreign lib paths
    std::vector<std::pair<uintptr_t,uintptr_t>> legit_data;        // legit lib r--/rw- segments
    std::vector<std::string> legit_data_path;
    std::map<std::string,uintptr_t> foreign_base;   // lowest addr per foreign .so (ELF base)
    std::vector<std::string> foreign_mod;           // module_id per foreign_ranges entry
    std::vector<std::pair<uintptr_t,uintptr_t>> anon_exec;  // [anon]/memfd exec (trampoline candidates)
    std::map<std::string,uintptr_t> legit_base;     // lowest addr per legit .so (for symbol resolution)
    std::vector<std::pair<uintptr_t,uintptr_t>> rwx_bounds;   // bounds of the kept RWX regions (INTEL_0052 enrichment)
    // Every executable region + a class, so an RWX region's trampoline stubs can be attributed:
    // L=legit code root, F=foreign injected .so, S=self (this lib), A=anon, M=memfd, O=other.
    struct ExecR { uintptr_t s, e; char cls; std::string mod; };
    std::vector<ExecR> exec_regions;

    size_t pos = 0;
    while (pos < maps.size()) {
        size_t eol = maps.find('\n', pos);
        size_t end = (eol == std::string::npos) ? maps.size() : eol;
        std::string line = maps.substr(pos, end - pos);
        pos = (eol == std::string::npos) ? maps.size() : eol + 1;
        if (line.empty()) continue;

        size_t first_space = line.find(' ');
        if (first_space == std::string::npos || first_space == 0 ||
            first_space + 5 >= line.size()) {
            continue;
        }
        std::string perms = line.substr(first_space + 1, 4);
        std::string range = line.substr(0, first_space);
        std::string path = extract_pathname(line);

        bool is_rwx = perms.size() == 4 && perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x';
        if (is_rwx) {
            if ((int)rwx_regions.size() < kRwxRegionLimit) {
                rwx_regions.push_back(path.empty() ? (range + " [anon]") : (range + " " + path));
                uintptr_t rs, re;
                rwx_bounds.push_back(range_bounds(range, &rs, &re) ? std::make_pair(rs, re)
                                                                   : std::make_pair((uintptr_t)0, (uintptr_t)0));
            } else {
                rwx_overflow++;
            }
            if (path.find("/memfd:jit-cache") != std::string::npos &&
                region_size(range) > kFridaMemfdJitMinSize) {
                memfd_regions.push_back(range + " " + path);
            }
        }
        // Signal A (provenance): executable code from outside the legit roots = injected.
        bool is_x = perms.size() == 4 && perms[2] == 'x';
        // Classify every executable region so RWX trampoline targets can be attributed (INTEL_0052 enrichment).
        if (is_x) {
            uintptr_t rs, re;
            if (range_bounds(range, &rs, &re)) {
                char cls; std::string mod;
                if (path.empty() || path[0] == '[')            cls = 'A';   // anon
                else if (path.rfind("/memfd:", 0) == 0)        cls = 'M';   // memfd
                else if (path == g_self_path)                  cls = 'S';   // this lib
                else if (path[0] == '/' && is_legit_code_root(path)) cls = 'L';
                else if (path[0] == '/' && !jit_anon(path)) { cls = 'F'; mod = module_id_from_path(path); }
                else                                           cls = 'O';
                exec_regions.push_back({rs, re, cls, mod});
            }
        }
        if (is_x && !path.empty() && path[0] == '/' && !is_legit_code_root(path) &&
            !jit_anon(path) && path != g_self_path) {
            uintptr_t rs, re;
            uintptr_t self_a = (uintptr_t)&range_bounds;
            if (range_bounds(range, &rs, &re) && !(self_a >= rs && self_a < re)) {
                foreign_ranges.push_back({rs, re});
                foreign_mod.push_back(module_id_from_path(path));
                if (foreign_paths.size() < 32 &&
                    std::find(foreign_paths.begin(), foreign_paths.end(), path) == foreign_paths.end())
                    foreign_paths.push_back(path);
            }
        }
        // Track the base (lowest addr) of each foreign .so, for the ELF enrichment read.
        if (!path.empty() && path[0] == '/' && !is_legit_code_root(path) && !jit_anon(path) &&
            path.find(".so") != std::string::npos) {
            uintptr_t rs, re;
            if (range_bounds(range, &rs, &re)) {
                auto it = foreign_base.find(path);
                if (it == foreign_base.end() || rs < it->second) foreign_base[path] = rs;
            }
        }
        // [anon]/memfd executable, non-JIT: candidate hook trampolines (Zygisk routes here).
        if (is_x && !jit_anon(path) && path != "[vdso]" &&
            (path.empty() || path[0] == '[' || path.rfind("/memfd:", 0) == 0)) {
            uintptr_t rs, re;
            if (range_bounds(range, &rs, &re)) anon_exec.push_back({rs, re});
        }
        // Base of each legit .so (for resolving the hooked symbol).
        if (!path.empty() && is_legit_code_root(path) && path.find(".so") != std::string::npos) {
            uintptr_t rs, re;
            if (range_bounds(range, &rs, &re)) {
                auto lb = legit_base.find(path);
                if (lb == legit_base.end() || rs < lb->second) legit_base[path] = rs;
            }
        }
        // Legit lib readable non-exec segments (.data/.got) — scanned for hijack pointers.
        if (perms.size() == 4 && perms[0] == 'r' && perms[2] != 'x' && !path.empty() &&
            is_legit_code_root(path) && path.find(".so") != std::string::npos) {
            uintptr_t rs, re;
            if (range_bounds(range, &rs, &re) && legit_data.size() < 512) {
                legit_data.push_back({rs, re}); legit_data_path.push_back(path);
            }
        }
        if (!path.empty()) {
            for (const auto& fw : kHookFrameworks) {
                bool hit = false;
                for (const char* sig : fw.sigs) {
                    if (sig && boundary_match(path, sig)) { hit = true; break; }
                }
                if (hit) {
                    bool seen = false;
                    for (const auto& f : frameworks) if (f == fw.canonical) { seen = true; break; }
                    if (!seen) frameworks.push_back(fw.canonical);
                }
            }
        }
    }
    if (rwx_overflow > 0) rwx_regions.push_back("... +" + std::to_string(rwx_overflow) + " more");

    // Signal A: foreign executable code mapped (provenance) — one record per distinct path.
    for (const auto& fp : foreign_paths) {
        std::string r = "foreign_text_mapped";
        r = append_field(r, "HIGH");
        r = append_field(r, "foreign exec mapping outside code roots");
        r = append_field(r, "path=" + fp);
        // C#1: module id from the mapping path (our own maps, no root file access needed).
        size_t mp = fp.find("/data/adb/modules/");
        if (mp != std::string::npos) {
            size_t ms = mp + 18;  // len("/data/adb/modules/")
            size_t me = fp.find('/', ms);
            if (me != std::string::npos && me > ms) r = append_field(r, "module_id=" + fp.substr(ms, me - ms));
        }
        // Signal C enrichment (fail-open): soname/DT_NEEDED + hook-lib hint from the mapped ELF.
        auto bit = foreign_base.find(fp);
        if (bit != foreign_base.end()) {
            std::string ce = enrich_from_base(bit->second);
            if (!ce.empty()) { r += kFS; r += ce; }
        }
        out.push_back(r);
    }

    // Signal B (false-positive-free): a pointer inside a legit library's data/GOT that points
    // INTO a foreign executable range is a hooked function pointer. No legitimate library ever
    // points into an injected module's code, so this has no benign cause. Reads via
    // process_vm_readv so an unreadable page returns EFAULT rather than faulting the process.
    if (!foreign_ranges.empty() && !legit_data.empty()) {
        static uintptr_t buf[2048];
        int emitted = 0;
        for (size_t i = 0; i < legit_data.size() && emitted < 16; ++i) {
            bool flagged = false;
            uintptr_t seg_s = legit_data[i].first, seg_e = legit_data[i].second;
            const std::string& lib = legit_data_path[i];
            uintptr_t lib_base = legit_base.count(lib) ? legit_base[lib] : 0;
            for (uintptr_t off = seg_s; off < seg_e && !flagged; off += sizeof(buf)) {
                size_t want = std::min((size_t)(seg_e - off), sizeof(buf));
                struct iovec lo{buf, want};
                struct iovec ro{(void*)off, want};
                ssize_t n = process_vm_readv(getpid(), &lo, 1, &ro, 1, 0);
                if (n <= 0) continue;
                for (size_t k = 0; k * sizeof(uintptr_t) < (size_t)n && !flagged; ++k) {
                    uintptr_t v = buf[k];
                    std::string mod;
                    // direct: the pointer lands inside a foreign module's code
                    for (size_t fi = 0; fi < foreign_ranges.size(); ++fi)
                        if (v >= foreign_ranges[fi].first && v < foreign_ranges[fi].second) { mod = foreign_mod[fi]; break; }
                    // trampoline hop: pointer lands in an [anon] region that references a foreign module
                    if (mod.empty())
                        for (const auto& ar : anon_exec)
                            if (v >= ar.first && v < ar.second) {
                                mod = trampoline_target(ar.first, ar.second, foreign_ranges, foreign_mod);
                                if (!mod.empty()) break;
                            }
                    if (mod.empty()) continue;   // no confirmed foreign target -> not a hijack (FP-safe)
                    uintptr_t slot = off + k * sizeof(uintptr_t);
                    std::string sym = lib_base ? resolve_reloc_symbol(lib_base, slot - lib_base) : "";
                    std::string r = "got_ptr_hijack";
                    r = append_field(r, "HIGH");
                    r = append_field(r, "GOT/data pointer targets foreign exec code");
                    r = append_field(r, "lib=" + lib);
                    if (!sym.empty()) r = append_field(r, "hooked_symbol=" + sym);
                    if (!mod.empty()) r = append_field(r, "hooked_by=" + mod);
                    out.push_back(r);
                    ++emitted; flagged = true; break;
                }
            }
        }
    }

    // Signal D (FP-free): a libc function whose PROLOGUE was rewritten to branch into
    // injected foreign code / an anon trampoline — an INLINE hook (Dobby/ShadowHook/
    // bytehook). These leave the GOT intact, so INTEL_0031 cannot see them. Double-gated:
    // the first instruction must decode as an unconditional branch AND its target must
    // land in a confirmed-foreign or anon-exec region. No legit libc prologue does this,
    // so it has no benign cause (an intra-legit ifunc/tail branch is ignored).
    {
        static const char* kHotFns[] = {
            "__system_property_get", "openat", "open", "faccessat", "access",
            "readlinkat", "readlink", "stat", "lstat", "fstatat", "fopen",
            "mmap", "ioctl", "connect", "kill", "ptrace", "fork",
        };
        int emitted = 0;
        for (const char* fn : kHotFns) {
            if (emitted >= 16) break;
            void* p = dlsym(RTLD_DEFAULT, fn);
            if (!p) continue;
            // Crash-safe read of the prologue bytes for the opcode-shape (INTEL_0008) check.
            uint8_t code[16];
            { struct iovec lo{code, sizeof(code)}, ro{p, sizeof(code)};
              if (process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) != (ssize_t)sizeof(code)) continue; }
            const bool is_abs_stub = prologue_looks_hooked(code);  // unambiguous LDR/BR|jmp stub only
            uintptr_t tgt = prologue_branch_target((uintptr_t)p);
            std::string mod; bool foreign = false;
            if (tgt) {
            for (size_t fi = 0; fi < foreign_ranges.size(); ++fi)
                if (tgt >= foreign_ranges[fi].first && tgt < foreign_ranges[fi].second) {
                    mod = foreign_mod[fi]; foreign = true; break;
                }
            if (!foreign)
                for (const auto& ar : anon_exec)
                    if (tgt >= ar.first && tgt < ar.second) {
                        // Anon trampoline: flag ONLY if it references injected FOREIGN code
                        // (same discipline as INTEL_0031). A legit app-bundled inline hooker
                        // (ShadowHook/bytehook/profilo) routes to its own /data/app .so, so its
                        // trampoline references legit code -> trampoline_target == "" -> not flagged.
                        bool found = false;
                        std::string m = trampoline_target(ar.first, ar.second, foreign_ranges,
                                                          foreign_mod, &found);
                        if (found) { foreign = true; mod = m; }   // name may be empty
                        break;
                    }
            }
            // INTEL_0008 (cleanup-resistant): the prologue IS an unambiguous absolute-jump stub,
            // but its target is NOT confirmed-foreign — a fully-cleaned inline hook (anon-only,
            // trampoline references legit code, module unmapped). INTEL_0003 goes silent here by
            // design (its FP-gate is provenance); this catches it by OPCODE SHAPE instead. FP-safe:
            // a legit compiled prologue is stack setup / a BTI landing pad, never an abs-jump stub;
            // benign per-device/version drift never produces one. (A legit app-bundled inline hooker
            // does splice a stub — that is a policy call, not a benign-drift FP; emitted HIGH/observe.)
            if (!foreign) {
                if (is_abs_stub) {
                    // ESCALATION: cross-check the prologue against the PRISTINE on-disk libc
                    // (raw-syscall read). If the on-disk prologue is ALSO an absolute-jump stub,
                    // this symbol is a legitimate thunk on this build -> suppress (kills the last
                    // theoretical FP). If it is a normal prologue, the in-memory stub is a CONFIRMED
                    // modification: carry the on-disk bytes as evidence. Fail-open: an unavailable
                    // read still emits (unconfirmed), never suppresses a real hook.
                    uint8_t disk[16];
                    bool have_disk = native_integrity::libc_ondisk_bytes((uintptr_t)p, disk, sizeof(disk));
                    if (have_disk && prologue_looks_hooked(disk)) continue;  // legit on-disk thunk -> not a hook
                    std::string r = "libc_inline_stub";
                    r = append_field(r, "HIGH");
                    r = append_field(r, "libc prologue: absolute-jump trampoline");
                    r = append_field(r, "hooked_symbol=" + std::string(fn));
                    char tb[40]; std::snprintf(tb, sizeof(tb), "target=%#lx", (unsigned long)tgt);
                    r = append_field(r, tb);
                    // ATTRIBUTION: follow the trampoline's branch chain to recover the culprit
                    // (relative branches / multi-stage trampolines that the level-1 pointer scan
                    // missed) and fingerprint the trampoline shape. Pure enrichment.
                    std::string tclass;
                    std::string culprit = trampoline_follow(tgt, foreign_ranges, foreign_mod, &tclass);
                    if (!tclass.empty()) r = append_field(r, "trampoline_class=" + tclass);
                    if (!culprit.empty()) r = append_field(r, "hooked_by=" + culprit);
                    if (have_disk) {
                        // Confirmed: on-disk prologue is a normal function entry, in-memory is a stub.
                        static const char kHex[] = "0123456789abcdef";
                        char hx[17];
                        for (int b = 0; b < 8; ++b) { hx[2*b] = kHex[disk[b] >> 4]; hx[2*b+1] = kHex[disk[b] & 0xF]; }
                        hx[16] = 0;
                        r = append_field(r, "ondisk_confirmed=1");
                        r = append_field(r, std::string("on_disk_prologue=") + hx);
                    }
                    out.push_back(r);
                    ++emitted;
                }
                continue;   // no confirmed-foreign target -> INTEL_0003 does not fire
            }
            std::string r = "libc_inline_hook";
            r = append_field(r, "HIGH");
            r = append_field(r, "libc prologue: branch into foreign code");
            r = append_field(r, "hooked_symbol=" + std::string(fn));
            if (!mod.empty()) r = append_field(r, "hooked_by=" + mod);
            char tb[40]; std::snprintf(tb, sizeof(tb), "target=%#lx", (unsigned long)tgt);
            r = append_field(r, tb);
            out.push_back(r);
            ++emitted;
        }
    }

    // hook_framework_present — one per distinct framework (HIGH).
    for (const auto& fw : frameworks) {
        std::string r = "hook_framework_present";
        r = append_field(r, "HIGH");
        r = append_field(r, "Hook framework library mapped into process address space (" + fw + ")");
        r = append_field(r, "framework=" + fw);
        out.push_back(r);
    }
    // INTEL_0052 enrichment: characterize one RWX region's contents. RWX presence alone is
    // ambiguous — a benign JIT is RWX too, holding only self-referential stubs (tramp=self) or
    // none; a hooker's trampoline pool holds absolute-jump stubs (LDR x16/x17,#8 ; BR ; .quad)
    // that branch into legit system code (a hook redirecting libc/libart — Frida/LSPlant class)
    // or into a foreign injected module (a Zygisk/Magisk module's hook). Exact-opcode match (no
    // imm19 guesswork), bounded, read-only via process_vm_readv. Pure enrichment on an already-
    // emitted record — never drives the verdict, so it adds no false-positive surface.
    struct RwxChar { int stubs = 0, to_self = 0, to_legit = 0, to_foreign = 0, to_other = 0; std::string mod; };
    auto characterize_rwx = [&](uintptr_t s, uintptr_t e) -> RwxChar {
        RwxChar c;
#if defined(__aarch64__)   // the stub shape (LDR x16/x17,#8 ; BR ; 8-byte .quad) is arm64-only
        if (s == 0 || e <= s) return c;
        size_t want = (size_t)std::min<uintptr_t>(e - s, (uintptr_t)(256u << 10));   // cap 256 KB
        std::vector<uint32_t> buf(want / 4);
        if (buf.empty()) return c;
        struct iovec lo{buf.data(), buf.size() * 4};
        struct iovec ro{reinterpret_cast<void*>(s), buf.size() * 4};
        ssize_t n = process_vm_readv(getpid(), &lo, 1, &ro, 1, 0);
        size_t nw = (n > 0) ? (size_t)n / 4 : 0;
        for (size_t i = 0; i + 3 < nw; ) {
            uint32_t w0 = buf[i], w1 = buf[i + 1];
            bool s16 = (w0 == 0x58000050u && w1 == 0xD61F0200u);   // LDR x16,#8 ; BR x16
            bool s17 = (w0 == 0x58000051u && w1 == 0xD61F0220u);   // LDR x17,#8 ; BR x17
            if (!(s16 || s17)) { i += 1; continue; }
            uintptr_t tgt = (uintptr_t)buf[i + 2] | ((uintptr_t)buf[i + 3] << 32);
            i += 4; c.stubs++;
            if (tgt >= s && tgt < e) { c.to_self++; continue; }
            char k = 0;
            for (const auto& R : exec_regions)
                if (tgt >= R.s && tgt < R.e) { k = R.cls; if (R.cls == 'F' && c.mod.empty()) c.mod = R.mod; break; }
            if (k == 'L' || k == 'S') c.to_legit++;
            else if (k == 'F')        c.to_foreign++;
            else                      c.to_other++;
        }
#else
        (void)s; (void)e;   // non-arm64: no stub decode; regions still reported as tramp=none
#endif
        return c;
    };

    // rwx_memory_mapping — single finding if any RWX region (HIGH), enriched per region.
    if (!rwx_regions.empty()) {
        std::string r = "rwx_memory_mapping";
        r = append_field(r, "HIGH");
        r = append_field(r, "writable+executable mapping detected");
        r = append_field(r, "region_count=" + std::to_string(rwx_regions.size()));
        int hook_stub_regions = 0;
        std::vector<std::string> region_fields;
        for (size_t i = 0; i < rwx_regions.size(); ++i) {
            std::string rf = rwx_regions[i];
            if (i < rwx_bounds.size()) {
                RwxChar c = characterize_rwx(rwx_bounds[i].first, rwx_bounds[i].second);
                const char* tramp = c.to_foreign > 0 ? "foreign"
                                  : c.to_legit   > 0 ? "legit"
                                  : c.to_self    > 0 ? "self"
                                  : c.stubs      > 0 ? "other" : "none";
                rf += " stubs=" + std::to_string(c.stubs) + " tramp=" + tramp;
                if (c.to_foreign > 0 && !c.mod.empty()) rf += ":" + c.mod;
                if (c.to_foreign > 0 || c.to_legit > 0) hook_stub_regions++;
            }
            region_fields.push_back(rf);
        }
        r = append_field(r, "hook_stub_regions=" + std::to_string(hook_stub_regions));
        r = append_field(r, std::string("likely_cause=") +
                              (hook_stub_regions > 0
                                 ? "hook trampoline pool (stubs branch into real code) — a hook redirecting libc/libart or a foreign module"
                                 : "RWX page present but no hook stubs resolved (self-referential/empty — e.g. a JIT code cache)"));
        for (size_t i = 0; i < region_fields.size(); ++i)
            r = append_field(r, "region_" + std::to_string(i) + "=" + region_fields[i]);
        out.push_back(r);
    }
    // frida_memfd_jit_present — single finding if any memfd JIT region (HIGH).
    if (!memfd_regions.empty()) {
        std::string r = "frida_memfd_jit_present";
        r = append_field(r, "HIGH");
        r = append_field(r, "foreign JIT/gum code range in maps");
        r = append_field(r, "region_count=" + std::to_string(memfd_regions.size()));
        for (size_t i = 0; i < memfd_regions.size(); ++i)
            r = append_field(r, "region_" + std::to_string(i) + "=" + memfd_regions[i]);
        out.push_back(r);
    }
}


}  // namespace env


// Orchestrator helper (spec 03 §1): true if /proc/self/maps shows an in-process
// hooking-framework trampoline (LSPosed/YAHFA/SandHook/Frida …). Used for the
// attestation⇄runtime correlation — a Verified-boot device that is also hooked
// is the strongest single tamper signal. Read failure -> false (fail-open).
bool runtime_hooking_present() {
    std::vector<std::string> recs;
    env::scan_runtime_maps(recs);
    for (const auto& r : recs)
        if (r.rfind("hook_framework_present", 0) == 0) return true;
    return false;
}

// INTEL_0059 — behavioral syscall divergence (query-only, side-effect-free). Checks faccessat
// AND the stat family. Ask libc
// faccessat (which a userspace hook may intercept) and a RAW `svc` faccessat that bypasses
// libc; flag ONLY when the kernel confirms existence (raw == 0) but libc denies it. This is
// mechanism-independent (inline/GOT/PLT/LD_PRELOAD all caught) and FP-free by construction:
// same syscall + same args agree on a clean device, we trust ONLY the kernel side as ground
// truth, and never flag on a failed/unavailable raw call.

}  // namespace dicore
