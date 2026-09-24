// Zip-embedded load leg of the obfuscation artifact check (task A1 fix round:
// the production load path with useLegacyPackaging=false, where the .so is
// mapped straight out of the APK — no offset-0 mapping of the library, maps
// entries carry ABSOLUTE apk file offsets).
//
// Builds a REAL minimal zip (one STORED entry "lib/x.so" whose data starts at
// a page-aligned offset B), mmaps the entry straight from the zip file — the
// kernel then shows the mapping with file offset exactly B, the zip entry's
// data offset — and feeds the resolver the real /proc/self/maps plus a marker
// address inside the mmap'd image:
//
//   whole-entry leg — one mapping at offset B (marker inside it);
//   linker-split leg — the exec page mprotect-split into an r-xp VMA at
//                      offset B + exec_off (the apk!/lib/... shape);
//   roundtrip        — the digest the resolver derives from the LIVE mapping
//                      must decrypt every digest-bound strtab entry of the
//                      artifact back to its marker plaintext.
//
// Never executes the mmap'd image (file-based, like tamper_check). Defensive
// shape is pinned by test_own_image's negatives; this leg pins the happy
// production path end to end through the real binder tool's artifact.
//
// usage: zip_load_check <bound-elf>   (writes <bound-elf>.zipload.zip)
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

#include "dicore/crypto/raw_sha256.h"
#include "dicore/platform/own_image.hpp"

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

using dicore::platform::own_image::ExecPage;
using dicore::platform::own_image::ResolvedExec;

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

static constexpr uint64_t kFlagBound = 1;
static constexpr uint64_t kFlagNever = 2;
static constexpr uint64_t kEndMagic = 0x524156454E4F4246ULL;  // legacy section magic (value stable)

static bool read_file(const char* path, std::string* out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::string s((size_t)f.tellg(), '\0');
    f.seekg(0);
    f.read(&s[0], (std::streamsize)s.size());
    *out = s;
    return f.good() || f.eof();
}

static uint64_t le64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

static uint32_t le32(const unsigned char* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put16(std::string* s, uint64_t v) {
    for (int i = 0; i < 2; ++i) s->push_back((char)((v >> (8 * i)) & 0xff));
}
static void put32(std::string* s, uint64_t v) {
    for (int i = 0; i < 4; ++i) s->push_back((char)((v >> (8 * i)) & 0xff));
}

// zip CRC-32 (reflected 0xEDB88320) — the entry is STORED, but the central
// directory still carries the CRC of the payload.
static uint32_t crc32_of(const std::string& d) {
    uint32_t c = 0xFFFFFFFF;
    for (char ch : d) {
        c ^= (uint8_t)ch;
        for (int k = 0; k < 8; ++k)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

struct Entry { uint64_t addr, len, key0, flags; };

// strtab/decrypt helpers mirrored from tamper_check.cpp (same contract).
static bool parse_strtab(const std::string& elf, std::vector<Entry>* out) {
    if (elf.size() < sizeof(Elf64_Ehdr)) return false;
    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf.data());
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return false;
    const bool is64 = eh->e_ident[EI_CLASS] == ELFCLASS64;
    const size_t shoff = (size_t)eh->e_shoff, shnum = eh->e_shnum, shent = eh->e_shentsize;
    if (shent < sizeof(Elf64_Shdr) || shoff == 0 || shnum == 0) return false;
    if (shoff >= elf.size() || shnum > (elf.size() - shoff) / shent) return false;
    const auto* shstr = reinterpret_cast<const Elf64_Shdr*>(elf.data() + shoff + eh->e_shstrndx * shent);
    if (shstr->sh_offset >= elf.size()) return false;
    const char* names = elf.data() + shstr->sh_offset;
    const size_t names_len = elf.size() - shstr->sh_offset;
    bool any = false;
    for (size_t i = 0; i < shnum; ++i) {
        const auto* sh = reinterpret_cast<const Elf64_Shdr*>(elf.data() + shoff + i * shent);
        if (sh->sh_name >= names_len) continue;
        if (strcmp(names + sh->sh_name, ".dicoreobf.strtab") != 0) continue;
        if (sh->sh_offset >= elf.size() || sh->sh_size % 32 != 0) return false;
        const unsigned char* p = reinterpret_cast<const unsigned char*>(elf.data()) + sh->sh_offset;
        size_t n = sh->sh_size / 32;
        for (size_t k = 0; k < n; ++k, p += 32) {
            Entry e{0, 0, 0, 0};
            e.addr = is64 ? le64(p) : (uint64_t)le32(p);
            e.len = le64(p + 8);
            e.key0 = le64(p + 16);
            e.flags = le64(p + 24);
            if (e.addr == 0 && e.flags == kEndMagic) continue;
            out->push_back(e);
        }
        any = true;
    }
    return any;
}

static bool va_to_off(const std::string& elf, uint64_t va, size_t* off) {
    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf.data());
    const size_t phoff = (size_t)eh->e_phoff, phnum = eh->e_phnum, phent = eh->e_phentsize;
    for (size_t i = 0; i < phnum; ++i) {
        const auto* ph = reinterpret_cast<const Elf64_Phdr*>(elf.data() + phoff + i * phent);
        if (ph->p_type != PT_LOAD) continue;
        if (va >= ph->p_vaddr && va < ph->p_vaddr + ph->p_filesz) {
            *off = (size_t)(ph->p_offset + (va - ph->p_vaddr));
            return true;
        }
    }
    return false;
}

static std::string xor_roll(const std::string& ct, uint64_t key) {
    std::string out(ct.size(), '\0');
    for (size_t i = 0; i < ct.size(); ++i)
        out[i] = (char)(ct[i] ^ (char)((key >> (8 * (i & 7))) & 0xff));
    return out;
}

static const char* kMarkers[] = {
    "DICOREOBFMARK_CLASS_com/dicoreobf/mark/K",
    "DICOREOBFMARK_PTR_NAME_r", "()Z",
    "DICOREOBFMARK_PTR_NAME_g", "(Ljava/lang/String;)Ljava/lang/String;",
    "(I)I",
    "DICOREOBFMARK_INL_NAME_a", "DICOREOBFMARK_INL_NAME_b",
};

static std::string read_maps() {
    std::ifstream f("/proc/self/maps");
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// Resolve through the real resolver over the REAL maps of the mmap'd image.
static bool resolve_marker(void* img, uintptr_t marker, ResolvedExec* ri) {
    std::string maps = read_maps();
    CHECK(!maps.empty());
    if (maps.empty()) return false;
    return dicore::platform::own_image::resolve_exec_page(maps.data(), maps.size(), marker, ri);
}

int main(int argc, char** argv) {
    if (argc != 2) { printf("usage: zip_load_check <bound-elf>\n"); return 2; }
    std::string elf;
    if (!read_file(argv[1], &elf)) { printf("FAIL read %s\n", argv[1]); return 1; }

    ExecPage ep{};
    CHECK(dicore::platform::own_image::exec_page(
        reinterpret_cast<const unsigned char*>(elf.data()), elf.size(), &ep));
    uintptr_t v0 = 0;
    {
        const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(elf.data());
        for (int i = 0; i < eh->e_phnum; ++i) {
            const auto* ph = reinterpret_cast<const Elf64_Phdr*>(
                elf.data() + eh->e_phoff + (size_t)i * eh->e_phentsize);
            if (ph->p_type == PT_LOAD) { v0 = (uintptr_t)ph->p_vaddr; break; }
        }
    }
    uint8_t filed[32];
    dicore::sha::raw_sha256(elf.data() + ep.offset, ep.len, filed);

    // ---- build the real minimal zip: STORED "lib/x.so" at data offset B --
    const uint64_t B = 0x40000;                       // page-aligned data offset
    const std::string name = "lib/x.so";
    const uint64_t extra = B - (30 + name.size());    // pad the local header
    const uint32_t crc = crc32_of(elf);
    std::string zip;
    zip.reserve((size_t)B + elf.size() + 128);
    put32(&zip, 0x04034b50); put16(&zip, 20); put16(&zip, 0); put16(&zip, 0);  // sig, ver, flags, stored
    put16(&zip, 0); put16(&zip, 0);                   // mtime, mdate
    put32(&zip, crc); put32(&zip, elf.size()); put32(&zip, elf.size());
    put16(&zip, name.size()); put16(&zip, extra);
    zip += name;
    zip.append((size_t)extra, '\0');
    CHECK(zip.size() == B);
    zip += elf;
    const uint64_t cd_off = zip.size();
    put32(&zip, 0x02014b50); put16(&zip, 20); put16(&zip, 20); put16(&zip, 0); put16(&zip, 0);
    put16(&zip, 0); put16(&zip, 0);
    put32(&zip, crc); put32(&zip, elf.size()); put32(&zip, elf.size());
    put16(&zip, name.size()); put16(&zip, 0); put16(&zip, 0);
    put16(&zip, 0); put16(&zip, 0); put32(&zip, 0); put32(&zip, 0);
    zip += name;
    const uint64_t cd_sz = zip.size() - cd_off;
    put32(&zip, 0x06054b50); put16(&zip, 0); put16(&zip, 0);
    put16(&zip, 1); put16(&zip, 1);
    put32(&zip, cd_sz); put32(&zip, cd_off); put16(&zip, 0);

    const std::string zpath = std::string(argv[1]) + ".zipload.zip";
    { std::ofstream f(zpath, std::ios::binary | std::ios::trunc); f.write(zip.data(), (std::streamsize)zip.size()); }

    int zfd = ::open(zpath.c_str(), O_RDONLY);
    CHECK(zfd >= 0);
    if (zfd < 0) return 1;
    const size_t span = (elf.size() + 0xFFF) & ~(size_t)0xFFF;
    void* img = ::mmap(nullptr, span, PROT_READ, MAP_PRIVATE, zfd, (off_t)B);
    CHECK(img != MAP_FAILED);
    if (img == MAP_FAILED) return 1;
    const uintptr_t marker = (uintptr_t)img + (ep.vaddr - v0) + 16;

    ResolvedExec ri{};
    // ---- whole-entry mapping: file offset == B (the entry data offset) --
    CHECK(resolve_marker(img, marker, &ri));
    CHECK(ri.base == (const uint8_t*)img);
    CHECK(ri.page == (const uint8_t*)img + (ep.vaddr - v0));
    uint8_t d[32];
    dicore::sha::raw_sha256(ri.page, ri.ep.len, d);
    CHECK(memcmp(d, filed, 32) == 0);

    // ---- linker-split mapping: r-xp VMA at B + exec page offset ---------
    const size_t x_page = (size_t)ep.offset & ~(size_t)0xFFF;
    CHECK(::mprotect((char*)img + x_page, 0x1000, PROT_READ | PROT_EXEC) == 0);
    CHECK(resolve_marker(img, marker, &ri));
    CHECK(ri.base == (const uint8_t*)img);
    dicore::sha::raw_sha256(ri.page, ri.ep.len, d);
    CHECK(memcmp(d, filed, 32) == 0);

    // ---- roundtrip: the LIVE zip-derived digest must decrypt the strtab
    const uint64_t d64 = dicore::platform::own_image::fold_digest128(d);
    std::vector<Entry> ents;
    CHECK(parse_strtab(elf, &ents));
    size_t bound_n = 0;
    std::vector<std::string> plains;
    for (const Entry& e : ents) {
        if (e.flags & kFlagNever) continue;
        size_t off = 0;
        CHECK(va_to_off(elf, e.addr, &off));
        if (!(e.flags & kFlagBound)) { printf("FAIL unbound entry in bind-leg artifact\n"); fails++; continue; }
        if (!va_to_off(elf, e.addr, &off) || off + e.len > elf.size()) continue;
        plains.push_back(xor_roll(elf.substr(off, (size_t)e.len), e.key0 ^ d64).c_str());
        bound_n++;
    }
    CHECK(bound_n >= 8);
    for (const char* m : kMarkers) {
        bool hit = false;
        for (const auto& p : plains) if (p == m) { hit = true; break; }
        if (!hit) { printf("FAIL zip-layout roundtrip missing marker: %s\n", m); fails++; }
    }

    ::munmap(img, span);
    ::close(zfd);
    ::unlink(zpath.c_str());
    printf(fails ? "OBF-ZIPLOAD FAIL\n" : "OBF-ZIPLOAD OK\n");
    return fails ? 1 : 0;
}
