// Host test for dicore/platform/own_image + crypto/raw_sha256 (plan task
// A1: digest-bound string keys). Pins the EXACT key-derivation contract the
// obfuscator pass (the obfuscating toolchain ctor emission), the POST_BUILD bind tool
// (tools/native/dicore-bind-strkeys.py) and the runtime decryptor must all
// agree on, plus the live-vs-file byte equality of our own exec page (the
// fixed-point assumption the whole binding rests on).
//
// Pure parts run against KAT vectors (independently produced with python
// hashlib) and a synthetic in-memory ELF buffer; the self-image check runs
// the real /proc/self/maps resolution against a /proc/self/exe read — on the
// host, exactly like on device (the same raw-syscall maps read, same phdr
// walk, same digest).
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "dicore/crypto/raw_sha256.h"
#include "dicore/platform/own_image.hpp"

#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)
#define CHECK_EQ_U64(got, want) do { uint64_t g_ = (got), w_ = (want); \
    if (g_ != w_) { printf("FAIL %s:%d %s: got 0x%016llx want 0x%016llx\n", \
        __FILE__, __LINE__, #got, (unsigned long long)g_, (unsigned long long)w_); fails++; } } while (0)

static uint64_t le64(const uint8_t* p) {
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 |
           (uint64_t)p[3] << 24 | (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 |
           (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}

// ---- raw_sha256: FIPS 180-4 KATs (python hashlib cross-checked) ----------
static void test_raw_sha256_kats() {
    uint8_t d[32];
    dicore::sha::raw_sha256("abc", 3, d);
    CHECK(memcmp(d,
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad", 32) == 0);
    dicore::sha::raw_sha256("", 0, d);
    CHECK(memcmp(d,
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32) == 0);
    // multi-block: 200 deterministic bytes → 5662cd43… (python hashlib)
    uint8_t big[200];
    for (size_t i = 0; i < sizeof(big); ++i) big[i] = (uint8_t)(i * 13 + 5);
    dicore::sha::raw_sha256(big, sizeof(big), d);
    CHECK(memcmp(d,
        "\x56\x62\xcd\x43\xa9\xa0\x88\x90\xf6\xee\xa1\x0b\x9c\xb3\x78\x54"
        "\x16\x3d\x54\x62\x9a\x5c\xa6\x04\xa0\x3e\x88\xc3\xce\x47\x41\x9f", 32) == 0);
}

// ---- fold / derive: the shared key formula (python cross-checked) --------
static void test_fold_derive() {
    uint8_t d[32];
    dicore::sha::raw_sha256("abc", 3, d);
    CHECK_EQ_U64(dicore::platform::own_image::fold_digest128(d), 0xc9edafd2615639fbULL);
    CHECK_EQ_U64(dicore::platform::own_image::derive_text_key(0x0123456789abcdefULL, d),
                 0xc8ceeab5e8fdf414ULL);
    dicore::sha::raw_sha256("", 0, d);
    CHECK_EQ_U64(dicore::platform::own_image::fold_digest128(d), 0x30a593018a304b79ULL);
    // tamper sensitivity: any flip in the first 16 digest bytes must move the fold
    uint8_t d2[32];
    dicore::sha::raw_sha256("abc", 3, d2);
    for (size_t i = 0; i < 16; ++i) {
        uint8_t d3[32]; memcpy(d3, d2, 32); d3[i] ^= 0x01;
        CHECK(dicore::platform::own_image::fold_digest128(d3) !=
              dicore::platform::own_image::fold_digest128(d2));
    }
}

// ---- exec_page over a synthetic ELF buffer -------------------------------
static void phdr64(uint8_t* buf, size_t idx, uint32_t type, uint32_t flags,
                   uint64_t off, uint64_t vaddr, uint64_t filesz) {
    Elf64_Phdr* ph = reinterpret_cast<Elf64_Phdr*>(buf + sizeof(Elf64_Ehdr) + idx * sizeof(Elf64_Phdr));
    memset(ph, 0, sizeof(*ph));
    ph->p_type = type; ph->p_flags = flags; ph->p_offset = off;
    ph->p_vaddr = vaddr; ph->p_filesz = filesz; ph->p_memsz = filesz;
    ph->p_align = 0x1000;
}

static void test_exec_page() {
    using dicore::platform::own_image::ExecPage;
    // 3 PT_LOADs: [0] RO at vaddr 0, [1] PF_X at vaddr 0x1000 (file 0x2000,
    // 0x8000 bytes), [2] RW. Exec page = first 4096 of segment [1].
    std::unique_ptr<uint8_t[]> img(new uint8_t[0x10000]);
    memset(img.get(), 0, 0x10000);
    Elf64_Ehdr* eh = reinterpret_cast<Elf64_Ehdr*>(img.get());
    memset(eh, 0, sizeof(*eh));
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 3;
    phdr64(img.get(), 0, PT_LOAD, PF_R, 0x0000, 0x0000, 0x1000);
    phdr64(img.get(), 1, PT_LOAD, PF_R | PF_X, 0x2000, 0x1000, 0x8000);
    phdr64(img.get(), 2, PT_LOAD, PF_R | PF_W, 0xa000, 0x9000, 0x1000);

    ExecPage ep{};
    CHECK(dicore::platform::own_image::exec_page(img.get(), 0x10000, &ep));
    CHECK(ep.vaddr == 0x1000);
    CHECK(ep.offset == 0x2000);
    CHECK(ep.len == 4096);  // p_filesz > kKeyPage → clamped

    // small exec segment (fixture-sized): whole p_filesz
    phdr64(img.get(), 1, PT_LOAD, PF_R | PF_X, 0x2000, 0x1000, 0x0800);
    CHECK(dicore::platform::own_image::exec_page(img.get(), 0x10000, &ep));
    CHECK(ep.len == 0x0800);

    // no PF_X → false; garbage → false; truncated phdr table → false
    phdr64(img.get(), 1, PT_LOAD, PF_R, 0x2000, 0x1000, 0x8000);
    CHECK(!dicore::platform::own_image::exec_page(img.get(), 0x10000, &ep));
    CHECK(!dicore::platform::own_image::exec_page(img.get(), 60, &ep));
    img.get()[0] = 0x7f; img.get()[1] = 0x45; img.get()[2] = 0x4c; img.get()[3] = 0x46;
    img.get()[EI_CLASS] = ELFCLASSNONE;
    CHECK(!dicore::platform::own_image::exec_page(img.get(), 0x10000, &ep));
}

// ---- self-image: live maps resolution == /proc/self/exe file bytes -------
static void test_self_image() {
    using namespace dicore::platform::own_image;
    uint8_t live[32];
    CHECK(exec_digest32(live));  // /proc/self/maps + phdr walk + raw_sha256

    // Independent path: read our own file, exec_page, hash the FILE bytes.
    int fd = ::open("/proc/self/exe", O_RDONLY);
    CHECK(fd >= 0);
    if (fd >= 0) {
        std::string exe;
        char tmp[4096]; ssize_t n;
        while ((n = ::read(fd, tmp, sizeof(tmp))) > 0) exe.append(tmp, (size_t)n);
        ::close(fd);
        CHECK(exe.size() > 64);
        ExecPage ep{};
        CHECK(exec_page((const uint8_t*)exe.data(), exe.size(), &ep));
        CHECK(ep.offset + ep.len <= exe.size());  // whole-file buffer: range contained
        uint8_t filed[32];
        dicore::sha::raw_sha256(exe.data() + ep.offset, ep.len, filed);
        CHECK(memcmp(live, filed, 32) == 0);

        uint64_t k = 0;
        CHECK(exec_key_material(&k));
        CHECK_EQ_U64(k, fold_digest128(filed));
    }
}

// ---- zip-embedded layouts: base derived from the marker's own mapping ----
// Mirrors the reviewer's probe (/tmp/opencode/t5-probe): a real page-aligned
// "apk" whose payload at offset B is a real ELF (our own image), mmap'd from
// B — so the KERNEL shows the mapping with file offset exactly B (the zip
// entry's data offset, not 0) — then mprotect-splitting the exec range to
// reproduce the linker's r-xp VMA at ABSOLUTE apk offsets. Both shapes must
// derive the same base and the same exec-page digest as the file bytes.
static std::string read_all(const char* path) {
    std::string out;
    int fd = ::open(path, O_RDONLY);
    if (fd < 0) return out;
    char tmp[4096]; ssize_t n;
    while ((n = ::read(fd, tmp, sizeof(tmp))) > 0) out.append(tmp, (size_t)n);
    ::close(fd);
    return out;
}

static void test_zip_layouts() {
    using namespace dicore::platform::own_image;
    const std::string exe = read_all("/proc/self/exe");
    CHECK(exe.size() > 64);
    ExecPage ep{};
    CHECK(exec_page((const uint8_t*)exe.data(), exe.size(), &ep));
    uintptr_t v0 = 0;
    {
        const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(exe.data());
        const auto* ph = reinterpret_cast<const Elf64_Phdr*>(exe.data() + eh->e_phoff);
        for (int i = 0; i < eh->e_phnum; ++i, ph = reinterpret_cast<const Elf64_Phdr*>(
                 (const char*)ph + eh->e_phentsize))
            if (ph->p_type == PT_LOAD) { v0 = (uintptr_t)ph->p_vaddr; break; }
    }
    uint8_t filed[32];
    dicore::sha::raw_sha256(exe.data() + ep.offset, ep.len, filed);

    // page-aligned "zip entry data offset" B with a page of apk prefix
    const uint64_t B = 0x40000;
    std::string zpath = "/tmp/t5_zip_layoutXXXXXX";
    std::vector<char> zbuf(zpath.begin(), zpath.end());
    zbuf.push_back('\0');
    int zfd = ::mkstemp(zbuf.data());
    zpath = zbuf.data();
    CHECK(zfd >= 0);
    if (zfd < 0) return;
    {
        std::string pad((size_t)B, '\0');
        CHECK(::write(zfd, pad.data(), pad.size()) == (ssize_t)pad.size());
        CHECK(::write(zfd, exe.data(), exe.size()) == (ssize_t)exe.size());
    }
    const size_t span = ((exe.size() + 0xFFF) & ~(size_t)0xFFF);
    void* img = ::mmap(nullptr, span, PROT_READ, MAP_PRIVATE, zfd, (off_t)B);
    CHECK(img != MAP_FAILED);
    if (img == MAP_FAILED) { ::close(zfd); ::unlink(zpath.c_str()); return; }

    // marker: an address inside the exec segment, at its runtime-layout
    // position (img is the image's file offset 0)
    const uintptr_t marker = (uintptr_t)img + (ep.vaddr - v0) + 16;
    ResolvedExec ri{};

    // ---- leg 1: whole-entry mapping — maps offset == B, not 0 ----------
    {
        std::string maps = read_all("/proc/self/maps");
        CHECK(!maps.empty());
        CHECK(resolve_exec_page(maps.data(), maps.size(), marker, &ri));
        CHECK(ri.base == (const uint8_t*)img);
        CHECK(ri.page == (const uint8_t*)img + (ep.vaddr - v0));
        uint8_t d[32];
        dicore::sha::raw_sha256(ri.page, ri.ep.len, d);
        CHECK(memcmp(d, filed, 32) == 0);
    }

    // ---- leg 2: linker-split mapping — r-xp VMA at B + exec page offset
    // (the production apk!/lib/... shape: absolute apk offsets, no off-0
    // mapping of the library anywhere)
    {
        const size_t x_page = (size_t)ep.offset & ~(size_t)0xFFF;
        CHECK(::mprotect((char*)img + x_page, 0x1000, PROT_READ | PROT_EXEC) == 0);
        std::string maps = read_all("/proc/self/maps");
        CHECK(!maps.empty());
        CHECK(resolve_exec_page(maps.data(), maps.size(), marker, &ri));
        CHECK(ri.base == (const uint8_t*)img);
        CHECK(ri.page == (const uint8_t*)img + (ep.vaddr - v0));
        uint8_t d[32];
        dicore::sha::raw_sha256(ri.page, ri.ep.len, d);
        CHECK(memcmp(d, filed, 32) == 0);

        // ---- defensive negatives (never guess, never fault) ------------
        // (a) only the marker's split VMA, header mapping withheld: no
        //     verifiable candidate → false, no crash. (Test-side parsing
        //     may use sscanf; the production TU may not.)
        std::string only_marker;
        for (size_t p = 0; p < maps.size();) {
            size_t eol = maps.find('\n', p);
            if (eol == std::string::npos) eol = maps.size();
            std::string line = maps.substr(p, eol - p + 1);
            unsigned long s = 0, e = 0;
            unsigned long long mo = 0;
            if (sscanf(line.c_str(), "%lx-%lx %*4s %llx", &s, &e, &mo) == 3 &&
                marker >= (uintptr_t)s && marker < (uintptr_t)e)
                only_marker += line;
            p = eol + 1;
        }
        CHECK(!only_marker.empty());
        CHECK(!resolve_exec_page(only_marker.c_str(), only_marker.size(), marker, &ri));
        // (b) a lying header candidate one page ABOVE the true entry data
        //     offset. Post path-column fix it IS derived as a candidate
        //     (its pathname matches the marker's) and dies on the probes:
        //     the arithmetic candidate lands on a non-ELF page inside the
        //     image (magic probe rejects), and the lie's own claimed
        //     mapping start (0x10000) is unmapped (fault-safe probe
        //     EFAULTs). Pre-fix it never became a candidate at all — *path
        //     pointed at the INODE column, so the lie's inode "0" mismatched
        //     the marker line's real inode inside the same-file comparison
        //     and the test passed for the wrong reason.
        char lie[256];
        int n = snprintf(lie, sizeof lie, "%lx-%lx r--p %llx 00:01 0 %s\n",
                         (unsigned long)0x10000, (unsigned long)0x11000,
                         (unsigned long long)(B + 0x1000), zpath.c_str());
        CHECK(n > 0 && (size_t)n < sizeof lie);
        std::string lied(only_marker);
        lied.insert(0, lie, (size_t)n);
        CHECK(!resolve_exec_page(lied.c_str(), lied.size(), marker, &ri));

        // ---- leg 3 (fix wave): same-file matching keys on the PATH column,
        // not the inode. The real leg-2 maps text with the HEADER r--p
        // line's inode digits rewritten to a different width — a mangled or
        // aliased view would report exactly that. Pre-fix (*path at the
        // inode column) the rewritten inode made header and marker lines
        // mismatch and the header candidate was never derived; post-fix the
        // pathname columns match and resolution succeeds exactly as leg 2.
        {
            std::string altered;
            bool rewrote = false;
            for (size_t p = 0; p < maps.size();) {
                size_t eol = maps.find('\n', p);
                if (eol == std::string::npos) eol = maps.size();
                std::string line = maps.substr(p, eol - p);
                unsigned long s = 0, e = 0;
                unsigned long long mo = 0;
                char pth[256] = {0};
                if (sscanf(line.c_str(), "%lx-%lx %*4s %llx %*s %*s %255[^\n]",
                           &s, &e, &mo, pth) == 4 &&
                    mo == B && pth == zpath &&       // the header r--p line
                    !(marker >= (uintptr_t)s && marker < (uintptr_t)e)) {
                    // rewrite the inode token (5th space-separated field)
                    size_t is = 0;
                    for (int tok = 0; tok < 4; ++tok)
                        is = line.find(' ', is) + 1;
                    size_t ie = line.find(' ', is);
                    if (ie == std::string::npos) ie = line.size();
                    line.replace(is, ie - is, "31337");
                    rewrote = true;
                }
                altered += line;
                altered += '\n';
                p = eol + 1;
            }
            CHECK(rewrote);
            CHECK(resolve_exec_page(altered.c_str(), altered.size(), marker, &ri));
            CHECK(ri.base == (const uint8_t*)img);
            CHECK(ri.page == (const uint8_t*)img + (ep.vaddr - v0));
            uint8_t d3[32];
            dicore::sha::raw_sha256(ri.page, ri.ep.len, d3);
            CHECK(memcmp(d3, filed, 32) == 0);
        }
    }

    ::munmap(img, span);
    ::close(zfd);
    ::unlink(zpath.c_str());
}

// ---- 16K-ABI vaddr/offset skew: the REAL shipped-image geometry ---------
// lld with -z max-page-size=16384 + --rosegment packs FILE offsets at 4K
// stride but lays VADDRS at 16K stride: p_vaddr - p_offset = 0x4000 for the
// exec PT_LOAD of the shipped arm64 image (0x8000 for the rw ones). On a
// 4K-page device with useLegacyPackaging=false the loader maps each PT_LOAD
// from the apk at ABSOLUTE offsets, so the marker's r-xp VMA sits (vaddr)
// 0x2e000 bytes above the image base while its apk file offset sits only
// (offset) 0x2a000 above the entry data offset — the old base = S-(F-Fj)
// arithmetic lands 0x4000 PAST the ELF header, the magic probe rejects every
// candidate, and every bound string decrypts to garbage on-device (the C1
// failure this regression pins). The loader-style layout is reproduced with
// MAP_FIXED file mappings whose VA<->offset shift encodes the skew exactly
// (each segment's VMA starts at floor(p_vaddr) with file offset B +
// floor(p_offset) — overlapping file coverage included, like the device).
static void test_zip_layouts_vaddr_skew() {
    using namespace dicore::platform::own_image;
    // Geometry scaled from the real arm64 phdrs (readelf -lW of the shipped
    // libdicore.so: LOAD0 off 0/vaddr 0, LOAD1 off 0x04a4e0/vaddr
    // 0x04e4e0, LOAD2 off 0x18fb10/vaddr 0x197b10):
    const uint64_t FSZ0 = 0x2a4d8;                       // LOAD0 R
    const uint64_t OFFX = 0x2a4e0, VAX = 0x2e4e0, FSZX = 0x9000;  // LOAD1 RX (skew 0x4000)
    const uint64_t OFFW = 0x34000, VAW = 0x3c000, FSZW = 0x1000;  // LOAD2 RW (skew 0x8000)
    const size_t file_span = 0x35000;
    const size_t va_span = 0x3d000;
    const uint64_t B = 0x40000;                          // apk entry data offset (16K-aligned)

    std::vector<uint8_t> file(file_span, 0);
    for (size_t i = 0; i < file_span; ++i) file[i] = (uint8_t)(i * 7 + 3);
    Elf64_Ehdr* eh = reinterpret_cast<Elf64_Ehdr*>(file.data());
    memset(eh, 0, sizeof(*eh));
    memcpy(eh->e_ident, ELFMAG, SELFMAG);
    eh->e_ident[EI_CLASS] = ELFCLASS64;
    eh->e_phoff = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum = 3;
    phdr64(file.data(), 0, PT_LOAD, PF_R, 0, 0, FSZ0);
    phdr64(file.data(), 1, PT_LOAD, PF_R | PF_X, OFFX, VAX, FSZX);
    phdr64(file.data(), 2, PT_LOAD, PF_R | PF_W, OFFW, VAW, FSZW);
    uint8_t filed[32];
    dicore::sha::raw_sha256(file.data() + OFFX, 4096, filed);

    // apk file: B bytes of prefix, then the image
    std::string zpath = "/tmp/t5_zip_skewXXXXXX";
    std::vector<char> zbuf(zpath.begin(), zpath.end());
    zbuf.push_back('\0');
    int zfd = ::mkstemp(zbuf.data());
    zpath = zbuf.data();
    CHECK(zfd >= 0);
    if (zfd < 0) return;
    {
        std::string pad((size_t)B, '\0');
        CHECK(::write(zfd, pad.data(), pad.size()) == (ssize_t)pad.size());
        CHECK(::write(zfd, file.data(), file.size()) == (ssize_t)file.size());
    }

    // Reserve the image's VA span, then MAP_FIXED each segment the way the
    // loader does: VMA start = base + floor(p_vaddr), backing file offset =
    // B + floor(p_offset) — the VA<->offset SHIFT is the skew under test.
    uint8_t* base = (uint8_t*)::mmap(nullptr, va_span, PROT_NONE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(base != MAP_FAILED);
    if (base == MAP_FAILED) { ::close(zfd); ::unlink(zpath.c_str()); return; }
    const uint64_t x_off_pg = OFFX & ~0xFFFULL, x_va_pg = VAX & ~0xFFFULL;
    const size_t x_len = (size_t)((OFFX + FSZX + 0xFFF) & ~0xFFFULL) - (size_t)x_off_pg;
    CHECK(::mmap(base, (size_t)((FSZ0 + 0xFFF) & ~0xFFFULL), PROT_READ,
                 MAP_FIXED | MAP_PRIVATE, zfd, (off_t)B) != MAP_FAILED);
    CHECK(::mmap(base + x_va_pg, x_len, PROT_READ | PROT_EXEC,
                 MAP_FIXED | MAP_PRIVATE, zfd, (off_t)(B + x_off_pg)) != MAP_FAILED);
    CHECK(::mmap(base + VAW, FSZW, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_PRIVATE, zfd, (off_t)(B + OFFW)) != MAP_FAILED);

    const uintptr_t marker = (uintptr_t)(base + VAX + 16);
    std::string maps = read_all("/proc/self/maps");
    CHECK(!maps.empty());

    ResolvedExec ri{};
    CHECK(resolve_exec_page(maps.data(), maps.size(), marker, &ri));
    CHECK(ri.base == base);
    // page = where file[p_offset] lives in VA — under the skew that is
    // base + p_vaddr (0x2e4e0), NOT the floored VMA start (0x2e000); the
    // digest bytes are identical either way (same file page).
    CHECK(ri.page == base + VAX);
    CHECK(ri.ep.offset == OFFX);
    uint8_t d[32];
    dicore::sha::raw_sha256(ri.page, ri.ep.len, d);
    CHECK(memcmp(d, filed, 32) == 0);

    ::munmap(base, va_span);
    ::close(zfd);
    ::unlink(zpath.c_str());
}

int main() {
    test_raw_sha256_kats();
    test_fold_derive();
    test_exec_page();
    test_self_image();
    test_zip_layouts();
    test_zip_layouts_vaddr_skew();
    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
