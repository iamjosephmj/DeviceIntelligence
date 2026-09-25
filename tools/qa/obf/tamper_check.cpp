// Tamper leg of the obfuscation artifact check (plan task A1: digest-bound
// string keys). Given an ELF that tools/native/dicore-bind-strkeys.py has
// bound, verifies BOTH directions of the binding at the artifact level:
//
//   clean  — decrypting every strtab entry with key0 XOR fold(sha256(first
//            exec page)) reproduces the expected DICOREOBFMARK_* plaintexts;
//   tamper — the same decryption against a copy whose exec first page was
//            flipped must NOT reproduce any marker (garbage keys), while the
//            NEVER_BIND entry (the INTEL_0042 digest array stand-in) still
//            decrypts with its seed-only key0 — INTEL_0042 stays independent
//            of the very .text an attacker patches.
//
// File-based by design (mmap/read the ELF, never execute it): a tampered
// image's ctor may decrypt garbage into NUL-less buffers, which is fine for
// this check but exactly why the leg does not dlopen. The live-ctor path is
// proven by the bound roundtrip leg in obf-check.sh.
//
// usage: tamper_check <bound-elf>   (writes/reads <bound-elf>.tampered)
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>

#include "dicore/crypto/raw_sha256.h"
#include "dicore/platform/own_image.hpp"

#include <elf.h>

using dicore::platform::own_image::ExecPage;

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

// flags contract (the obfuscating toolchain emission / dicore-bind-strkeys.py patching —
// keep all three in lock-step)
static constexpr uint64_t kFlagBound = 1;      // set by the bind tool
static constexpr uint64_t kFlagNever = 2;      // set by the pass (exemption)
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

struct Entry {
    uint64_t addr, len, key0, flags;
};

// Locate every `.dicoreobf.strtab` section (post-link usually one) and parse
// its 32-byte entries up to the end marker. The addr field is a typed
// pointer: u64 on ELF64, u32 (padded) on ELF32 — mirrored from the old pass format.
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
            if (e.addr == 0 && e.flags == kEndMagic) continue;  // per-TU marker
            if (e.flags & ~(kFlagBound | kFlagNever)) return false;
            if ((e.flags & kFlagBound) && (e.flags & kFlagNever)) return false;
            out->push_back(e);
        }
        any = true;
    }
    return any;
}

// File offset of a VA via PT_LOADs.
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

// key material over an image's exec first page (file bytes) — mirrors the
// bind tool and the runtime ctor.
static bool page_key(const std::string& elf, uint64_t* out) {
    ExecPage ep{};
    if (!dicore::platform::own_image::exec_page(
            reinterpret_cast<const unsigned char*>(elf.data()), elf.size(), &ep))
        return false;
    if (ep.offset + ep.len > elf.size()) return false;
    uint8_t d[32];
    dicore::sha::raw_sha256(elf.data() + ep.offset, ep.len, d);
    *out = dicore::platform::own_image::fold_digest128(d);
    return true;
}

// rolling-key byte XOR — the same 8-byte rotation the strxor pass applies.
static std::string xor_roll(const std::string& ct, uint64_t key) {
    std::string out(ct.size(), '\0');
    for (size_t i = 0; i < ct.size(); ++i)
        out[i] = (char)(ct[i] ^ (char)((key >> (8 * (i & 7))) & 0xff));
    return out;
}

static std::string decrypt_entry(const std::string& elf, const Entry& e, uint64_t d64,
                                 bool bound) {
    size_t off = 0;
    if (!va_to_off(elf, e.addr, &off) || off + e.len > elf.size()) return {};
    std::string ct = elf.substr(off, (size_t)e.len);
    uint64_t key = e.key0 ^ (bound ? d64 : 0);
    return xor_roll(ct, key);
}

static const char* kMarkers[] = {
    "DICOREOBFMARK_CLASS_com/dicoreobf/mark/K",
    "DICOREOBFMARK_PTR_NAME_r", "()Z",
    "DICOREOBFMARK_PTR_NAME_g", "(Ljava/lang/String;)Ljava/lang/String;",
    "(I)I",
    "DICOREOBFMARK_INL_NAME_a", "DICOREOBFMARK_INL_NAME_b",
};
// the digest-array stand-in: the pass may encrypt only its non-zero prefix
// (clang splits a trailing-zero array into struct leaves), so compare the
// entry's own length as a prefix of the expected 32 bytes
static const unsigned char kDigestBytes[32] = {
    'R','A','V','E','N','O','B','F','M','A','R','K','_','D','I','G','E','S','T',
    'B','A','S','E', 0,0,0,0,0,0,0,0,0};

int main(int argc, char** argv) {
    if (argc != 2) { printf("usage: tamper_check <bound-elf>\n"); return 2; }
    std::string elf;
    if (!read_file(argv[1], &elf)) { printf("FAIL read %s\n", argv[1]); return 1; }

    std::vector<Entry> ents;
    if (!parse_strtab(elf, &ents)) { printf("FAIL no parseable .dicoreobf.strtab\n"); return 1; }

    size_t bound_n = 0, never_n = 0;
    for (const Entry& e : ents) (e.flags & kFlagNever) ? never_n++ : bound_n++;
    CHECK(bound_n >= 8);   // the leg must have teeth
    // >=1: the INTEL_0042 digest stand-in, plus the kNoBind diagnostic
    // strings (log tag, formats) that must stay seed-decryptable by design.
    CHECK(never_n >= 1);

    // ---- clean pass: every bound entry decrypts to a known marker --------
    uint64_t d64 = 0;
    CHECK(page_key(elf, &d64));
    if (!d64) { printf("FAIL page_key\n"); return 1; }
    std::vector<std::string> plains;
    const Entry* digest_entry = nullptr;
    for (const Entry& e : ents) {
        std::string pt = decrypt_entry(elf, e, d64, /*bound=*/!(e.flags & kFlagNever));
        if (e.flags & kFlagNever) {
            // content-identified: the digest stand-in is the never entry whose
            // seed-only plaintext is the marker (never entries now also
            // include the kNoBind diagnostic strings)
            // clang may split the zero-tailed array into leaves, so the
            // stand-in is identified by its text prefix, not its length
            if (pt.size() >= 12 &&
                memcmp(pt.data(), kDigestBytes, 12) == 0)
                digest_entry = &e;
            continue;
        }
        plains.push_back(pt.c_str());  // NUL-terminated view
    }
    CHECK(digest_entry != nullptr);
    for (const char* m : kMarkers) {
        bool hit = false;
        for (const auto& p : plains) if (p == m) { hit = true; break; }
        if (!hit) { printf("FAIL clean decrypt missing marker: %s\n", m); fails++; }
    }
    // the NEVER_BIND entry decrypts seed-only to the exact digest bytes
    CHECK(digest_entry != nullptr);
    if (digest_entry) {
        std::string d = decrypt_entry(elf, *digest_entry, d64, /*bound=*/false);
        CHECK(digest_entry && d.size() == digest_entry->len && d.size() <= 32 && memcmp(d.data(), kDigestBytes, d.size()) == 0);
    }

    // ---- tampered pass: exec first page flipped → binding must break -----
    ExecPage ep{};
    CHECK(dicore::platform::own_image::exec_page(
        reinterpret_cast<const unsigned char*>(elf.data()), elf.size(), &ep));
    std::string tam = elf;
    // flip 8 bytes past the phdr table (offset 2048 is inside the first page
    // for any real image and beyond every phdr table we produce)
    const size_t flip = (size_t)ep.offset + 2048;
    CHECK(flip + 8 <= tam.size());
    for (int i = 0; i < 8; ++i) tam[flip + i] = (char)(tam[flip + i] ^ 0x5a);
    std::string tam_path = std::string(argv[1]) + ".tampered";
    { std::ofstream f(tam_path, std::ios::binary); f.write(tam.data(), (std::streamsize)tam.size()); }

    uint64_t d64t = 0;
    CHECK(page_key(tam, &d64t));
    CHECK(d64t != d64);
    int still = 0;
    for (const Entry& e : ents) {
        if (e.flags & kFlagNever) continue;
        std::string pt = decrypt_entry(tam, e, d64t, /*bound=*/true);
        for (const char* m : kMarkers)
            if (pt.c_str() == std::string(m)) { ++still; break; }
    }
    CHECK(still == 0);  // no bound string may survive a .text patch
    if (digest_entry) {
        // INTEL_0042 independence: seed-only decryption still exact on the
        // tampered image
        std::string d = decrypt_entry(tam, *digest_entry, d64t, /*bound=*/false);
        CHECK(digest_entry && d.size() == digest_entry->len && d.size() <= 32 && memcmp(d.data(), kDigestBytes, d.size()) == 0);
    }

    printf(fails ? "OBF-TAMPER FAIL\n" : "OBF-TAMPER OK\n");
    return fails ? 1 : 0;
}
