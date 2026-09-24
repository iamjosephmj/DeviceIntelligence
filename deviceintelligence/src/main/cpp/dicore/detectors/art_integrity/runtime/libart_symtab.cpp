#include "dicore/detectors/art_integrity/runtime/libart_symtab.h"

#include "dicore/platform/log.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <link.h>

namespace dicore::art_integrity {

namespace {

struct LibArtSymtab {
    uintptr_t base = 0;
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t sym_count = 0;
    bool ready = false;
};

LibArtSymtab g_libart_symtab;

size_t gnu_hash_sym_count(const uint32_t* gnu_hash) {
    // GNU hash header (per glibc / bionic spec):
    //   uint32_t nbuckets;
    //   uint32_t symoffset;   // index of first sym in chain
    //   uint32_t bloom_size;  // ElfW(Addr) entries
    //   uint32_t bloom_shift;
    //   ElfW(Addr) bloom[bloom_size];
    //   uint32_t  buckets[nbuckets];
    //   uint32_t  chain[];    // length = total_dynsym - symoffset
    //
    // To compute total_dynsym we find max(buckets[*]) and walk the chain from
    // there until the LSB-terminator is hit.
    const uint32_t nbuckets = gnu_hash[0];
    const uint32_t symoffset = gnu_hash[1];
    const uint32_t bloom_size = gnu_hash[2];
    const auto* buckets = reinterpret_cast<const uint32_t*>(
        reinterpret_cast<const ElfW(Addr)*>(gnu_hash + 4) + bloom_size);
    const uint32_t* chain = buckets + nbuckets;
    uint32_t max_sym = symoffset;
    for (uint32_t i = 0; i < nbuckets; ++i) {
        if (buckets[i] > max_sym) max_sym = buckets[i];
    }
    if (max_sym < symoffset) return symoffset;
    // Walk forward from max_sym until LSB is set (last in chain).
    uint32_t idx = max_sym;
    for (uint32_t i = 0; i < 100000; ++i) {
        const uint32_t entry = chain[idx - symoffset];
        if (entry & 1u) {
            ++idx;
            break;
        }
        ++idx;
    }
    return idx;
}

int find_libart_symtab_cb(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    if (!info->dlpi_name) return 0;
    const char* name = info->dlpi_name;
    const size_t name_len = std::strlen(name);
    constexpr const char kSuffix[] = "libart.so";
    constexpr size_t kSuffixLen = sizeof(kSuffix) - 1;
    if (name_len < kSuffixLen ||
        std::strcmp(name + name_len - kSuffixLen, kSuffix) != 0) {
        return 0;
    }

    auto* out = static_cast<LibArtSymtab*>(data);
    out->base = info->dlpi_addr;

    const ElfW(Phdr)* dyn_phdr = nullptr;
    for (uint16_t i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn_phdr = &info->dlpi_phdr[i];
            break;
        }
    }
    if (!dyn_phdr) return 1;
    const auto* dyn = reinterpret_cast<const ElfW(Dyn)*>(info->dlpi_addr + dyn_phdr->p_vaddr);

    const uint32_t* gnu_hash = nullptr;
    const uint32_t* sysv_hash = nullptr;
    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                out->symtab = reinterpret_cast<const ElfW(Sym)*>(
                    info->dlpi_addr + d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                out->strtab = reinterpret_cast<const char*>(
                    info->dlpi_addr + d->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                gnu_hash = reinterpret_cast<const uint32_t*>(
                    info->dlpi_addr + d->d_un.d_ptr);
                break;
            case DT_HASH:
                sysv_hash = reinterpret_cast<const uint32_t*>(
                    info->dlpi_addr + d->d_un.d_ptr);
                break;
            default:
                break;
        }
    }
    if (!out->symtab || !out->strtab) return 1;
    if (sysv_hash) {
        // SysV hash[1] = nchain = number of symtab entries.
        out->sym_count = sysv_hash[1];
    } else if (gnu_hash) {
        out->sym_count = gnu_hash_sym_count(gnu_hash);
    } else {
        // Neither hash table available — fall back to a generous upper bound.
        // Linear scan still works, just less efficiently and with a small risk
        // of walking into the next ELF section.
        out->sym_count = 50000;
    }
    out->ready = true;
    return 1;
}

}  // namespace

bool libart_symtab_ready() {
    if (g_libart_symtab.ready) return true;
    ::dl_iterate_phdr(&find_libart_symtab_cb, &g_libart_symtab);
    if (!g_libart_symtab.ready) return false;
    RLOGI("F18 Vector D: libart base=0x%lx symtab=%p strtab=%p sym_count=%zu",
          static_cast<unsigned long>(g_libart_symtab.base),
          g_libart_symtab.symtab,
          g_libart_symtab.strtab,
          g_libart_symtab.sym_count);
    return true;
}

const void* lookup_libart_symbol(const char* name) {
    if (!g_libart_symtab.ready) return nullptr;
    for (size_t i = 0; i < g_libart_symtab.sym_count; ++i) {
        const ElfW(Sym)& s = g_libart_symtab.symtab[i];
        if (s.st_name == 0 || s.st_value == 0) continue;
        const char* sym_name = g_libart_symtab.strtab + s.st_name;
        if (std::strcmp(sym_name, name) == 0) {
            return reinterpret_cast<const void*>(g_libart_symtab.base + s.st_value);
        }
    }
    return nullptr;
}

}  // namespace dicore::art_integrity
