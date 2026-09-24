// own_image.cpp — resolve our own image's exec page and derive the
// digest-bound key material (see own_image.hpp for the design contract and
// why this avoids every dl* call).
//
// CTOR-TIME DISCIPLINE: this runs from init_array constructors, possibly
// before libc++/malloc-heavy paths are warm, always while this TU's own
// obfuscated code is executing, and BEFORE any strenc ciphertext in the
// image is decrypted. It therefore uses NO std::string, NO heap, NO libc
// parsers — raw syscalls into a stack buffer and hand-rolled parsing only.
// (An earlier revision read through svc::read_file/std::string/strtoull;
// under the full obfuscation stack at ctor time that chain proved fragile.)

#include "dicore/platform/own_image.hpp"
#include <csetjmp>
#include <csignal>

#include "dicore/crypto/raw_sha256.h"
#include "dicore/platform/syscalls.h"

#include <cstdint>
#include <cstring>
#include <link.h>   // ElfW(...)
#include <fcntl.h>   // AT_FDCWD, O_RDONLY
#include <sys/types.h>

// (seed-decryptable) even when exec-page resolution fails.

namespace dicore::platform::own_image {
namespace {

// "/proc/self/maps" XOR 0x5a — the one byte string the digest resolver needs
// BEFORE any strenc ciphertext is decrypted (the digest IS the key material).
// Ordinary string literals in this TU are encrypted by the pass, which would
// make the ctor-time open read garbage — and a plain stack array is memcpy'd
// from exactly such an encrypted literal. The section pin keeps the strenc
// pass off this global (it skips section-pinned data), the volatile keeps the
// compiler from constant-folding the de-XOR into a fresh encryptable literal,
// and the mask keeps the well-known path out of the binary in plaintext.
const volatile unsigned char kMapsPathX[16] __attribute__((section(".dicoreobf.clear"))) = {
    '/' ^ 0x5a, 'p' ^ 0x5a, 'r' ^ 0x5a, 'o' ^ 0x5a, 'c' ^ 0x5a, '/' ^ 0x5a,
    's' ^ 0x5a, 'e' ^ 0x5a, 'l' ^ 0x5a, 'f' ^ 0x5a, '/' ^ 0x5a, 'm' ^ 0x5a,
    'a' ^ 0x5a, 'p' ^ 0x5a, 's' ^ 0x5a, 0 ^ 0x5a};

// Bounds: /proc/self/maps of an Android app process runs a few tens of KB;
// 256 KiB covers pathological cases. Two bytes of slack for the line scan.
constexpr size_t kMapsCap = 1024 * 1024;  // Android 17: apps have far more mappings

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse [p, end) as hex into *out; advances *p past the hex run.
// Returns false when no hex digit was consumed.
bool parse_hex(const char** p, const char* end, uintptr_t* out) {
    uintptr_t v = 0;
    const char* q = *p;
    bool any = false;
    while (q < end) {
        const int h = hex_val(*q);
        if (h < 0) break;
        v = (v << 4) | (uintptr_t)h;
        ++q;
        any = true;
    }
    *p = q;
    *out = v;
    return any;
}

// One maps line [p, end): fill start/end/file-offset and point *path at the
// start of the PATH column (the remainder of the line — kernel paths may
// contain spaces; the pointer is NUL- or end-terminated by the caller's
// context) or set it null for anonymous mappings (no path column at all).
// "start-end perms offset dev inode path" — columns walked, never sscanf'd.
// Token boundaries skipped after the offset: dev and inode are each one
// token, so the third space-run lands at the path column (the marker for
// same-file matching is the PATHNAME, never the inode — different-mount or
// mangled views may report differing inode digits for the same file).
bool maps_fields(const char* p, const char* end, uintptr_t* start, uintptr_t* end_,
                 uint64_t* file_off, const char** path) {
    if (!parse_hex(&p, end, start) || p >= end || *p != '-') return false;
    ++p;
    if (!parse_hex(&p, end, end_)) return false;
    if (*end_ <= *start) return false;
    // skip perms column (single token)
    while (p < end && *p == ' ') ++p;
    while (p < end && *p != ' ') ++p;
    if (p >= end) return false;
    while (p < end && *p == ' ') ++p;                   // offset column
    uintptr_t off = 0;
    if (!parse_hex(&p, end, &off)) return false;
    // skip the dev and inode tokens (two more space-run boundaries), then
    // the path column starts (may be absent: anonymous mapping)
    int tokens = 0;
    while (p < end && tokens < 3) {
        if (*p == ' ') {
            ++tokens;
            while (p < end && *p == ' ') ++p;
        } else {
            ++p;
        }
    }
    *file_off = (uint64_t)off;
    *path = (p < end && *p != ' ') ? p : nullptr;
    return true;
}

// Whole-file /proc/self/maps read: raw open/read loop into a stack buffer
// (the kernel materializes the file per-read; stop at EOF or cap).
bool read_maps_stack(char* buf, size_t cap, size_t* len) {
    // Android 17: the /proc/self symlink may not resolve for apps (ENOENT
    // errno=2 capture). Candidates in order; first successful open wins.
    static const char kNoBind_MapsThread[] = "/proc/thread-self/maps";
    static const char kNoBind_ProcDir[] = "/proc/";
    static const char kNoBind_MapsSfx[] = "/maps";
    char path[48];
    for (size_t i = 0; i < 16; ++i) path[i] = (char)(kMapsPathX[i] ^ 0x5a);
    int err = 0;
    int fd = dicore::sys::raw_openat(AT_FDCWD, path, O_RDONLY, 0, &err);
    if (fd < 0) {
        fd = dicore::sys::raw_openat(AT_FDCWD, kNoBind_MapsThread,
                                        O_RDONLY, 0, &err);
    }
    if (fd < 0) {
        const int pid = dicore::sys::raw_getpid(&err);
        if (pid > 0) {
            size_t w = 6;
            memcpy(path, kNoBind_ProcDir, w);
            char digits[12];
            int n = 0;
            int p = pid;
            while (p > 0 && n < 12) { digits[n++] = (char)('0' + p % 10); p /= 10; }
            while (n > 0) path[w++] = digits[--n];
            const size_t sfx_len = strlen(kNoBind_MapsSfx);
            memcpy(path + w, kNoBind_MapsSfx, sfx_len);
            path[w + sfx_len] = '\0';
            fd = dicore::sys::raw_openat(AT_FDCWD, path, O_RDONLY, 0, &err);
        }
    }
    if (fd < 0) {
        return false;
    }
    size_t got = 0;
    for (;;) {
        if (got >= cap) {
            dicore::sys::raw_close(fd);
            return false;
        }
        const ssize_t n = dicore::sys::raw_read(fd, buf + got, cap - got, &err);
        if (n < 0) {
            dicore::sys::raw_close(fd);
            return false;
        }
        if (n == 0) break;
        got += (size_t)n;
    }
    dicore::sys::raw_close(fd);
    *len = got;
    return true;
}

bool elf_magic(const uint8_t* p) {
    return p[0] == 0x7f && p[1] == 'E' && p[2] == 'L' && p[3] == 'F';
}

// Link-time vaddr AND file offset of the FIRST PT_LOAD (the load-bias
// anchor pair): for our lld-built images both are 0, but compute them
// instead of assuming.
bool first_load_span(const uint8_t* img, size_t len, uintptr_t* v0,
                     uint64_t* p_off0) {
    if (!img || len < 64 || !elf_magic(img)) return false;
    const auto* eh = reinterpret_cast<const ElfW(Ehdr)*>(img);
    const size_t phoff = (size_t)eh->e_phoff;
    const size_t phnum = eh->e_phnum;
    const size_t phentsize = eh->e_phentsize;
    if (phentsize < sizeof(ElfW(Phdr)) || phnum == 0) return false;
    if (phoff >= len || phnum > (len - phoff) / phentsize) return false;
    for (size_t i = 0; i < phnum; ++i) {
        const auto* ph = reinterpret_cast<const ElfW(Phdr)*>(img + phoff + i * phentsize);
        if (ph->p_type == PT_LOAD) {
            *v0 = (uintptr_t)ph->p_vaddr;
            *p_off0 = (uint64_t)ph->p_offset;
            return true;
        }
    }
    return false;
}

// Bounds for the fault-safe candidate probes: an ehdr + phdr table bigger
// than a page has never come out of our toolchain (lld/ld tables run a few
// hundred bytes); anything past this fails closed.
constexpr size_t kPhdrWinCap = 4096;

// Coarsest kernel page we support when comparing maps-reported file offsets:
// a 16K-page loader (Pixel 10 Pro class) floors BOTH the header and exec
// mappings into the 16K grid, so the observed offset difference can fall
// SHORT of the exec segment's true 4K file stride by up to one 16K page
// (64K headroom covers 64K-page arm64 kernels). See the 16K loader test.
constexpr uint64_t kMaxKernelPage = 65536;

// Verify one derived base (see resolve_exec_page for where it comes from).
// `is_self_mapping`: the candidate IS the marker's mapping (whole-image
// layout: the mapping starts at the image's file offset 0, so the ELF
// header sits at its start and the digest page must be contained in it).
// Otherwise the candidate is hypothesized to be the first PT_LOAD's
// mapping, and the exec mapping must sit exactly `d` file bytes above it —
// the offset identity every loader layout satisfies. Every read is
// fault-safe: a wrong candidate costs an EFAULT, never a SIGSEGV.
bool verify_base(uintptr_t base, uint64_t d, bool is_self_mapping,
                 uintptr_t self_s, uintptr_t self_e, ResolvedExec* out,
                 const char** why) {
    int err = 0;
    uint8_t hdr[64];
    if (dicore::sys::raw_self_read((const void*)base, sizeof hdr, hdr, &err) !=
        (ssize_t)sizeof hdr) {
        if (why) *why = "hdr-read";
        return false;
    }
    if (!elf_magic(hdr)) {
        if (why) *why = "no-magic";
        return false;
    }
    ElfW(Ehdr) eh;
    memcpy(&eh, hdr, sizeof eh);
#if defined(__LP64__)
    if (eh.e_ident[EI_CLASS] != ELFCLASS64) return false;
#else
    if (eh.e_ident[EI_CLASS] != ELFCLASS32) return false;
#endif
    const uint64_t win = (uint64_t)eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize;
    if (win == 0 || win > kPhdrWinCap) {
        if (why) *why = "phdr-win";
        return false;
    }
    uint8_t ph[kPhdrWinCap];
    if (dicore::sys::raw_self_read((const void*)base, (size_t)win, ph, &err) !=
        (ssize_t)win) {
        if (why) *why = "phdr-read";
        return false;
    }
    ExecPage ep{};
    if (!exec_page(ph, (size_t)win, &ep)) {
        if (why) *why = "no-exec-phdr";
        return false;
    }
    uintptr_t v0 = 0;
    uint64_t p_off0 = 0;
    if (!first_load_span(ph, (size_t)win, &v0, &p_off0)) {
        if (why) *why = "no-first-load";
        return false;
    }
    if (ep.vaddr < v0 || ep.offset < p_off0) {
        if (why) *why = "seg-order";
        return false;
    }
    const uintptr_t page = base + (uintptr_t)(ep.vaddr - v0);
    if (is_self_mapping) {
        if (page < self_s || ep.len > (size_t)(self_e - page)) {
            if (why) *why = "self-span";
            return false;
        }
    } else {
        // 4K devices: d IS the exec segment's page-floored file stride.
        // 16K devices: both mappings are floored into the coarse grid, so d
        // falls SHORT of the true stride by less than one kernel page (the
        // correct header-mapping candidate must NOT be rejected for that —
        // the Pixel 10 Pro abort). A wrong candidate's d is unrelated to
        // the stride by far more than a page.
        const uint64_t stride = ep.offset - p_off0;
        if (d > stride || stride - d >= kMaxKernelPage) {
            if (why) *why = "offset-id";
            return false;
        }
    }
    // the digest page itself must be readable before anyone hashes it
    uint8_t probe[kKeyPage];
    if (dicore::sys::raw_self_read((const void*)page, ep.len, probe, &err) !=
        (ssize_t)ep.len) {
        if (why) *why = "page-read";
        return false;
    }
    out->base = (const uint8_t*)base;
    out->ep = ep;
    out->v0 = v0;
    out->page = (const uint8_t*)page;
    return true;
}

}  // namespace

uint64_t fold_digest128(const uint8_t sha[32]) {
    uint64_t lo = 0, hi = 0;
    for (int i = 0; i < 8; ++i) {
        lo = lo | ((uint64_t)sha[i] << (8 * i));
        hi = hi | ((uint64_t)sha[8 + i] << (8 * i));
    }
    return lo ^ hi;
}

uint64_t derive_text_key(uint64_t key0, const uint8_t sha[32]) {
    return key0 ^ fold_digest128(sha);
}

bool exec_page(const uint8_t* image, size_t image_len, ExecPage* out) {
    // Header + phdr-table walk only — see the hpp contract for why the
    // segment itself is described, not bounds-checked into the window.
    if (!image || !out || image_len < sizeof(ElfW(Ehdr))) return false;
    const auto* eh = reinterpret_cast<const ElfW(Ehdr)*>(image);
    if (!elf_magic(image)) return false;
#if defined(__LP64__)
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return false;
#else
    if (eh->e_ident[EI_CLASS] != ELFCLASS32) return false;
#endif
    const size_t phoff = (size_t)eh->e_phoff;
    const size_t phnum = eh->e_phnum;
    const size_t phentsize = eh->e_phentsize;
    if (phentsize < sizeof(ElfW(Phdr)) || phnum == 0) return false;
    if (phoff >= image_len || phnum > (image_len - phoff) / phentsize) return false;
    for (size_t i = 0; i < phnum; ++i) {
        const auto* ph = reinterpret_cast<const ElfW(Phdr)*>(image + phoff + i * phentsize);
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X)) continue;
        const uint64_t fsz = (uint64_t)ph->p_filesz;
        if (fsz == 0) return false;
        out->offset = (uint64_t)ph->p_offset;
        out->vaddr = (uintptr_t)ph->p_vaddr;
        out->len = fsz < (uint64_t)kKeyPage ? (size_t)fsz : kKeyPage;
        return true;
    }
    return false;
}

// The base derivation, and why "find the off-0 mapping" failed in
// production: with useLegacyPackaging=false the .so is NOT extracted — the
// loader maps each PT_LOAD straight out of base.apk, and /proc/self/maps
// reports those mappings under the APK's path with ABSOLUTE apk file
// offsets (the apk!/lib/... layout). No offset-0 mapping of the library
// exists, so the old scan found no base and every bound string decrypted to
// garbage on every real device load.
//
// What holds in EVERY layout (extracted file, whole-entry zip mapping,
// linker-split apk mappings) is that the ELF header is AT a mapping start
// or at a page-arithmetic distance from the marker's mapping:
//     base = S_m − (F_m − F_j)          (offset arithmetic; valid while
//                                        p_vaddr strides == p_offset strides)
//     base = S_j                        (j's mapping starts at the header —
//                                        the device's header mapping; valid
//                                        even under the 16K-ABI vaddr/offset
//                                        skew, where the arithmetic candidate
//                                        lands inside the image and is
//                                        rejected by the magic probe)
// — the zip-entry offset cancels in the difference (this refines the
// probe-proven formula  base = map_start − (map_fileoff −
// zip_entry_data_offset)  with the entry offset recovered from the header
// mapping instead of known). Candidates are never trusted: each derived
// base is probed fault-safely, must show ELF magic AT the base itself,
// must walk to a PF_X phdr, and must satisfy the offset identity
// (verify_base). A mapping of another image in the same apk derives to an
// address that is unmapped or not an ELF header at its own offset —
// rejected; the residual cross-image coincidence fails open (garbage
// keys), never crashes.
bool resolve_exec_page(const char* maps, size_t maps_len, uintptr_t marker,
                       ResolvedExec* out) {
    if (!maps || !out || maps_len == 0) return false;
    const char* const maps_end = maps + maps_len;

    // 1) which file-backed mapping contains this TU's code?
    uintptr_t self_s = 0, self_e = 0;
    uint64_t self_off = 0;
    const char* self_path = nullptr;
    size_t self_path_len = 0;
    const char* line = maps;
    while (line < maps_end) {
        const char* eol = (const char*)memchr(line, '\n', (size_t)(maps_end - line));
        eol = eol ? eol : maps_end;
        uintptr_t s = 0, e = 0;
        uint64_t off = 0;
        const char* path = nullptr;
        if (maps_fields(line, eol, &s, &e, &off, &path) && path &&
            marker >= s && marker < e) {
            self_s = s;
            self_e = e;
            self_off = off;
            self_path = path;
            self_path_len = (size_t)(eol - path);
            break;
        }
        line = eol + 1;
    }
    if (!self_path) {
        return false;
    }
    // 2) derive the ELF base from the marker's own mapping arithmetic
    line = maps;
    while (line < maps_end) {
        const char* eol = (const char*)memchr(line, '\n', (size_t)(maps_end - line));
        eol = eol ? eol : maps_end;
        uintptr_t s = 0, e = 0;
        uint64_t off = 0;
        const char* path = nullptr;
        if (maps_fields(line, eol, &s, &e, &off, &path) && path &&
            off <= self_off &&
            (size_t)(eol - path) == self_path_len &&
            memcmp(path, self_path, self_path_len) == 0) {
            const uint64_t d = self_off - off;
            const bool is_self = (s == self_s && off == self_off);
            // Candidate A (arithmetic): assumes the marker's VMA sits exactly
            // d file-bytes above j's mapping start — i.e. that
            // (p_vaddr - v0) == (p_offset - p_off0) for the exec segment.
            // True for 4K-congruent images (offsets == vaddrs), FALSE for the
            // shipped 16K-ABI layout (-z max-page-size=16384 packs file
            // offsets at 4K stride while vaddrs stride 16K: the exec PT_LOAD
            // of libdicore.so has p_vaddr - p_offset = 0x4000), where A
            // lands 0x4000 past the header and the magic probe rejects it.
            // Candidate B (mapping start): j's mapping itself begins at the
            // ELF header (the loader's header mapping) — the device layout.
            // Both are probed fault-safely and must pass verify_base (magic
            // at the base, PF_X phdr, offset identity vs d) before use.
            // unsigned subtraction on purpose: an impossible candidate
            // underflows to an unmapped address and the fault-safe probe
            // rejects it (EFAULT, no signal)
            const uintptr_t base_a = self_s - (uintptr_t)d;
            const char* why_a = nullptr;
            const char* why_b = nullptr;
            if (verify_base(base_a, d, is_self, self_s, self_e, out, &why_a))
                return true;
            if (verify_base(s, d, false, self_s, self_e, out, &why_b)) return true;
        }
        line = eol + 1;
    }
    return false;
}

// Maps-less fallback: Android 17 denies apps procfs maps reads (observed on
// the Pixel 10 Pro farm device — every ctor logged "maps read failed", D
// degraded to 0, and all bound strings stayed ciphertext). This resolver
// never touches /proc: the CALLER's own code address is by definition inside
// our executable mapping, so walk page-by-page downward from its floor page,
// probing fault-safely for the ELF header, then run the same verification
// verify_base applies (magic, walkable phdrs, exec phdr, readable digest
// page) plus the anchor check that the marker address itself lies inside the
// found exec segment's virtual span. Works on any page granularity: the base
// page-aligned-ness of the loader's mappings only changes WHERE the header
// sits, and the walk stops at the first magic that passes verification.
// Fault-safe probe WITHOUT signals or process_vm_readv: writing the
// candidate range to /dev/null makes the KERNEL walk the page tables —
// EFAULT on any unmapped/PROT_NONE page, len on a readable one. No signal
// handler is involved, so nothing breaks under binary-translation bridges
// (the SIGSEGV-guarded variant faulted fatally inside berberis's memcpy
// trampoline). The bytes themselves are then plain-copied (proven readable).
// Layer-3 SIGSEGV guard state (see probe_read layer 3). Plain statics, NOT
// thread_local: emutls access inside a signal handler is unsafe under
// binary-translation bridges.
static sigjmp_buf g_probe_jmp;
static volatile sig_atomic_t g_probe_active = 0;

static void probe_sigsegv_handler(int, siginfo_t*, void*) {
    if (g_probe_active) siglongjmp(g_probe_jmp, 1);
    signal(SIGSEGV, SIG_DFL);  // not our fault — die honestly
}

static int g_probe_nullfd = -2;  // -2 = not opened, -1 = open failed

static bool probe_read(void* dst, const void* src, size_t len) {
    if (len == 0) return true;
    int err = 0;
    // Layer 1: kernel-mediated self read (process_vm_readv) — fault-safe by
    // design, no signals.
    if (dicore::sys::raw_self_read(src, len, dst, &err) == (ssize_t)len)
        return true;
    // Layer 2: kernel-mediated readability check via /dev/null — write()
    // returns EFAULT for any unreadable byte, then a plain copy is safe.
    if (g_probe_nullfd == -2)
        g_probe_nullfd = dicore::sys::raw_openat(-100 /*AT_FDCWD*/,
                                                    "/dev/null", 0, 0, nullptr);
    if (g_probe_nullfd >= 0 &&
        dicore::sys::raw_write(g_probe_nullfd, src, len, &err) ==
            (ssize_t)len) {
        memcpy(dst, src, len);
        return true;
    }
    // Layer 3 (last resort): direct read under a SIGSEGV guard. Works
    // wherever signals work.
    struct sigaction sa{}, oldsa{};
    sa.sa_sigaction = probe_sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &oldsa);
    g_probe_active = 1;
    bool ok = true;
    if (sigsetjmp(g_probe_jmp, 1) == 0) {
        memcpy(dst, src, len);
    } else {
        ok = false;
    }
    g_probe_active = 0;
    sigaction(SIGSEGV, &oldsa, nullptr);
    return ok;
}


static bool resolve_by_walkdown(uintptr_t marker, ResolvedExec* out) {
    const uintptr_t start = marker & ~(uintptr_t)(kKeyPage - 1);
    constexpr size_t kMaxWalkPages = 4096;  // 16 MiB — 16K-page layouts walk farther
    for (size_t i = 0; i < kMaxWalkPages; i++) {
        const uintptr_t cand = start - i * kKeyPage;
        uint8_t hdr[64];
        if (!probe_read(hdr, (const void*)cand, sizeof hdr))
            continue;  // unmapped guard page — keep walking
        if (!elf_magic(hdr)) continue;
        ElfW(Ehdr) eh;
        memcpy(&eh, hdr, sizeof eh);
#if defined(__LP64__)
        if (eh.e_ident[EI_CLASS] != ELFCLASS64) continue;
#else
        if (eh.e_ident[EI_CLASS] != ELFCLASS32) continue;
#endif
        const uint64_t win =
            (uint64_t)eh.e_phoff + (uint64_t)eh.e_phnum * eh.e_phentsize;
        if (win == 0 || win > kPhdrWinCap) continue;
        uint8_t ph[kPhdrWinCap];
        if (!probe_read(ph, (const void*)cand, (size_t)win)) continue;
        ExecPage ep{};
        if (!exec_page(ph, (size_t)win, &ep)) continue;
        uintptr_t v0 = 0;
        uint64_t p_off0 = 0;
        if (!first_load_span(ph, (size_t)win, &v0, &p_off0)) continue;
        if (ep.vaddr < v0 || ep.offset < p_off0) continue;
        const uintptr_t page = cand + (uintptr_t)(ep.vaddr - v0);
        // anchor: the marker must sit inside this candidate's image virtual
        // span (first PT_LOAD vaddr .. max vaddr+memsz) — a coincidental
        // ELF-magic data page has our code nowhere in its exec range.
        uintptr_t span_end = v0;
        for (size_t k = 0; k + sizeof(ElfW(Phdr)) <= (size_t)win;
             k += eh.e_phentsize) {
            ElfW(Phdr) ph2;
            memcpy(&ph2, ph + k, sizeof ph2);
            if (ph2.p_type != PT_LOAD) continue;
            const uintptr_t end =
                (uintptr_t)ph2.p_vaddr + (uintptr_t)ph2.p_memsz;
            if (end > span_end) span_end = end;
        }
        if (marker < page || marker >= cand + span_end) continue;
        uint8_t probe[kKeyPage];
        if (!probe_read(probe, (const void*)page, ep.len)) continue;
        out->base = (const uint8_t*)cand;
        out->ep = ep;
        out->v0 = v0;
        out->page = (const uint8_t*)page;
        return true;
    }
    return false;
}

bool exec_digest32(uint8_t out[32]) {
    if (!out) return false;
    // One resolution per thread (W5): a release image has ~71 strenc ctors
    // on the loading thread; the first computes and caches the digest, the
    // rest copy it. Failure is not cached — an unreadable /proc stays loud.
    static thread_local int t_state = 0;  // 0 = unset, 1 = resolved
    static thread_local uint8_t t_digest[32];
    if (t_state == 1) {
        memcpy(out, t_digest, 32);
        return true;
    }
    // The maps buffer lives in thread_local storage (NOT the ctor-time
    // stack): 256 KiB is nothing to risk against small thread stacks, and
    // later components on tiny stacks inherit the cache above instead.
    static thread_local char maps_buf[kMapsCap];
    size_t maps_len = 0;
    if (!read_maps_stack(maps_buf, kMapsCap, &maps_len)) {
        ResolvedExec ri{};
        const uintptr_t marker = (uintptr_t)(const void*)&exec_digest32;
        if (!resolve_by_walkdown(marker, &ri)) {
            return false;
        }
        dicore::sha::raw_sha256(ri.page, ri.ep.len, out);
        memcpy(t_digest, out, 32);
        t_state = 1;
        return true;
    }
    ResolvedExec ri{};
    const uintptr_t marker = (uintptr_t)(const void*)&exec_digest32;
    if (!resolve_exec_page(maps_buf, maps_len, marker, &ri)) {
        // Android 17 denies apps procfs maps reads — the maps path can never
        // succeed there. Fall back to the maps-less page walk before giving
        // up (walkdown failure is NOT cached either: stays loud per retry).
        if (!resolve_by_walkdown(marker, &ri)) {
            return false;
        }
    }
    dicore::sha::raw_sha256(ri.page, ri.ep.len, out);
      memcpy(t_digest, out, 32);
    t_state = 1;
    return true;
}

bool exec_key_material(uint64_t* out) {
    if (!out) return false;
    uint8_t d[32];
    if (!exec_digest32(d)) return false;
    *out = fold_digest128(d);
    return true;
}

}  // namespace dicore::platform::own_image

extern "C" uint64_t dicore_exec_text_key64() {
    uint64_t k = 0;
    if (!dicore::platform::own_image::exec_key_material(&k)) {
        return 0;
    }
    return k;
}
