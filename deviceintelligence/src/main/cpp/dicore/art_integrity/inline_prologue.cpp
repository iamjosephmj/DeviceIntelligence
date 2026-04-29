#include "inline_prologue.h"

#include "../log.h"
#include "../sha256.h"

#include <android/api-level.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <mutex>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

namespace dicore::art_integrity {

namespace {

// ----------------------------------------------------------------
// Target table — mangled C++ symbols exported by libart.so.
//
// Empirical reason for the mangled-name choice: the obvious
// `art_quick_*` assembly stubs (e.g. `art_quick_invoke_stub`)
// are built with `-fvisibility=hidden` in modern AOSP and do
// NOT appear in libart's `.dynsym`. Even reading the in-memory
// dynamic symbol table can't surface them. The C++ entry points
// listed here, by contrast, ARE exported with default visibility
// because other libs in the ART APEX call them.
//
// They're also the more interesting hook targets in practice:
//
//  - `art::ArtMethod::Invoke` — the entry point for ALL
//    reflective Java invocation (`Method.invoke`, `Constructor
//    .newInstance`, …). Frida-Java hooks land here when they
//    intercept method calls.
//  - `art::ClassLinker::FindClass` — class-load hot path; both
//    `Class.forName` and JNI `FindClass` go through it.
//  - `art::JavaVMExt::LoadNativeLibrary` — the
//    `System.loadLibrary` handler. Hooking here is the standard
//    way to detect / interpose on every .so load.
//  - `art::JNIEnvExt::GetFunctionTable` — used by Frida-Java to
//    obtain the JNINativeInterface pointer for Vector C-style
//    table tampering.
//  - `JNI_GetCreatedJavaVMs` / `JNI_CreateJavaVM` — invocation
//    interface entry points; common for headless attach.
//
// All of these resolve via `dlsym` from an app-namespace
// process because they have default visibility and are not on
// the Android linker's app-process exclusion list.
// ----------------------------------------------------------------
const char* const kSymbols[] = {
    // art::ArtMethod::Invoke(Thread*, uint32_t*, uint32_t, JValue*, char const*)
    "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc",
    // art::ClassLinker::FindClass(Thread*, char const*, size_t, Handle<mirror::ClassLoader>)
    "_ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEE",
    // art::JavaVMExt::LoadNativeLibrary(JNIEnv*, std::string const&, jobject, jclass, std::string*)
    "_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_",
    // art::JNIEnvExt::GetFunctionTable(bool)
    "_ZN3art9JNIEnvExt16GetFunctionTableEb",
    // art::JNIEnvExt::NewLocalRef(art::mirror::Object*)
    "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE",
    // art::JNIEnvExt::DeleteLocalRef(_jobject*)
    "_ZN3art9JNIEnvExt14DeleteLocalRefEP8_jobject",
    // art::Thread::QuickDeliverException(bool)
    "_ZN3art6Thread21QuickDeliverExceptionEb",
    // art::WellKnownClasses::Init(JNIEnv*) — called once at runtime startup
    "_ZN3art16WellKnownClasses4InitEP7_JNIEnv",
    // Public JNI invocation interface entry points.
    "JNI_GetCreatedJavaVMs",
    "JNI_CreateJavaVM",
};
constexpr size_t kSymbolCount = sizeof(kSymbols) / sizeof(kSymbols[0]);
static_assert(kSymbolCount <= kInlineMaxTargets,
              "kInlineMaxTargets must accommodate every kSymbols entry");

// ----------------------------------------------------------------
// Embedded baseline table.
//
// Populated via the M8 "extract" workflow:
//   1. Build the SDK with all M8 code in place.
//   2. Run `NativeBridge.artIntegrityExtractPrologueBaseline()`
//      on a known-clean device.
//   3. The returned strings are `"<symbol>|<api_int>|<hex_bytes>"`.
//   4. Paste a matching `BaselineEntry` row into [kBaselines]
//      below, keeping the table sorted by api/symbol for
//      readability.
//
// Symbols + APIs without a row are scanned for drift but skipped
// for baseline-mismatch — the absence of an embedded baseline
// is NOT a finding, just a coverage gap.
// ----------------------------------------------------------------
struct BaselineEntry {
    int api_int;
    const char* symbol;
    uint8_t bytes[kPrologueBytes];
};

// Per-arch baseline tables. Only symbols whose first
// `kPrologueBytes` are byte-identical across multiple clean
// devices on a given API are embedded here. Symbols whose
// prologues contain PC-relative branches or offsets (which
// legitimately vary per-build at the same API) are deliberately
// omitted to avoid swamping the report with `baseline_mismatch`
// false positives. The drift check (snapshot vs live) catches
// post-load tampering for those symbols just as well.
//
// To extend the table:
//   1. Run `NativeBridge.artIntegrityExtractPrologueBaseline()`
//      on multiple clean devices of the target API.
//   2. Compare outputs across devices; only embed rows where
//      every clean device produced the same 16-byte prefix.
//   3. Paste matching rows here; keep the table sorted by
//      api_int then symbol for human-friendly diffing.
#if defined(__aarch64__)
const BaselineEntry kBaselines[] = {
    // API 36 — Pixel 9 Pro (Tensor G4) + Pixel 6 Pro (Tensor G1)
    {36, "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc",
     {0xff,0x43,0x02,0xd1,0xfd,0x7b,0x05,0xa9,
      0xf8,0x5f,0x06,0xa9,0xf6,0x57,0x07,0xa9}},
    {36, "_ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEE",
     {0xff,0x43,0x05,0xd1,0xfd,0x7b,0x0f,0xa9,
      0xfc,0x6f,0x10,0xa9,0xfa,0x67,0x11,0xa9}},
    {36, "_ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectP7_jclassPS9_",
     {0xff,0xc3,0x04,0xd1,0xfd,0x7b,0x0d,0xa9,
      0xfc,0x6f,0x0e,0xa9,0xfa,0x67,0x0f,0xa9}},
    {36, "_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE",
     {0xff,0x43,0x01,0xd1,0xfd,0x7b,0x03,0xa9,
      0xf4,0x4f,0x04,0xa9,0xfd,0xc3,0x00,0x91}},
    {36, "_ZN3art6Thread21QuickDeliverExceptionEb",
     {0xfd,0x7b,0xba,0xa9,0xfc,0x6f,0x01,0xa9,
      0xfa,0x67,0x02,0xa9,0xf8,0x5f,0x03,0xa9}},
    {36, "_ZN3art16WellKnownClasses4InitEP7_JNIEnv",
     {0xfd,0x7b,0xbd,0xa9,0xf5,0x0b,0x00,0xf9,
      0xf4,0x4f,0x02,0xa9,0xfd,0x03,0x00,0x91}},
    {36, "JNI_GetCreatedJavaVMs",
     {0xe8,0x03,0x1f,0x2a,0xe1,0x00,0x00,0x34,
      0x89,0x1f,0x00,0xb0,0x29,0x69,0x40,0xf9}},
    {36, "JNI_CreateJavaVM",
     {0xff,0xc3,0x02,0xd1,0xfd,0x7b,0x06,0xa9,
      0xf9,0x3b,0x00,0xf9,0xf8,0x5f,0x08,0xa9}},
};
#else
// x86_64 baselines — not yet harvested. Run the
// extract helper on an x86_64 emulator + add rows here.
// (Empty arrays aren't standard C++, so we expose a zero
// pointer instead.)
const BaselineEntry* const kBaselines = nullptr;
#endif

#if defined(__aarch64__)
constexpr size_t kBaselineCount = sizeof(kBaselines) / sizeof(kBaselines[0]);
#else
constexpr size_t kBaselineCount = 0;
#endif

const BaselineEntry* find_baseline(int api_int, const char* symbol) {
    for (size_t i = 0; i < kBaselineCount; ++i) {
        if (kBaselines[i].api_int == api_int &&
            std::strcmp(kBaselines[i].symbol, symbol) == 0) {
            return &kBaselines[i];
        }
    }
    return nullptr;
}

// ----------------------------------------------------------------
// Resolved-symbol table. Built once at init.
// ----------------------------------------------------------------
struct ResolvedTarget {
    const char* symbol = nullptr;
    const void* addr = nullptr;
    bool resolved = false;
};

ResolvedTarget g_targets[kInlineMaxTargets] = {};
size_t g_resolved_count = 0;

// ----------------------------------------------------------------
// In-memory ELF dynsym walker.
//
// The Android linker namespace mechanism (API 24+) blocks app
// processes from `dlsym`'ing into `libart.so` — the call returns
// NULL even for symbols that ARE present in `libart`'s `.dynsym`
// with default visibility. The restriction is deliberate: ART
// internals are not part of the NDK contract.
//
// To resolve targets reliably we bypass dlsym entirely and walk
// libart's loaded ELF image directly:
//   1. `dl_iterate_phdr` callback finds libart's load bias and
//      program headers (we already do this for ranges.cpp).
//   2. Locate the `PT_DYNAMIC` segment inside libart.
//   3. Iterate `Elf64_Dyn` entries to pluck out `DT_SYMTAB`,
//      `DT_STRTAB`, and `DT_HASH` / `DT_GNU_HASH`.
//   4. Compute the dynsym entry count from the hash table
//      (DT_HASH directly encodes it; DT_GNU_HASH requires
//      a pass over its buckets and chains).
//   5. Linear-scan the dynsym, comparing each symbol name
//      against our target list.
//
// This bypass is well-known and shipped in many production
// Android security tools; it doesn't elevate privilege and
// only reads memory the linker already mapped read-only.
// ----------------------------------------------------------------

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
    // To compute total_dynsym we find max(buckets[*]) and walk
    // the chain from there until the LSB-terminator is hit.
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
        // Neither hash table available — fall back to a
        // generous upper bound. Linear scan will still work,
        // just less efficiently and with a small risk of
        // walking into the next ELF section.
        out->sym_count = 50000;
    }
    out->ready = true;
    return 1;
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

void resolve_targets() {
    if (!g_libart_symtab.ready) {
        ::dl_iterate_phdr(&find_libart_symtab_cb, &g_libart_symtab);
        if (!g_libart_symtab.ready) {
            RLOGW("F18 Vector D: libart symtab walker failed (no PT_DYNAMIC?)");
            return;
        }
        RLOGI("F18 Vector D: libart base=0x%lx symtab=%p strtab=%p sym_count=%zu",
              static_cast<unsigned long>(g_libart_symtab.base),
              g_libart_symtab.symtab,
              g_libart_symtab.strtab,
              g_libart_symtab.sym_count);
    }
    for (size_t i = 0; i < kSymbolCount; ++i) {
        g_targets[i].symbol = kSymbols[i];
        g_targets[i].addr = lookup_libart_symbol(kSymbols[i]);
        g_targets[i].resolved = (g_targets[i].addr != nullptr);
        if (g_targets[i].resolved) ++g_resolved_count;
        RLOGI("F18 Vector D: %-50s -> %p (%s)",
              kSymbols[i], g_targets[i].addr,
              g_targets[i].resolved ? "ok" : "missing");
    }
    RLOGI("F18 Vector D: resolved %zu/%zu libart symbols",
          g_resolved_count, kSymbolCount);
}

// ----------------------------------------------------------------
// Self-protected baseline storage. One mmap page for the bytes
// (kInlineMaxTargets * kPrologueBytes = 256 bytes), one for the
// SHA-256 hash. Same protection cycle as the other vectors.
// ----------------------------------------------------------------
struct PrologueStorage {
    void* values_page = nullptr;   // uint8_t[kInlineMaxTargets][kPrologueBytes]
    void* hash_page = nullptr;     // uint8_t[32] + padding
    size_t page_size = 0;
};

PrologueStorage g_storage;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes = kInlineMaxTargets * kPrologueBytes;

bool ensure_pages_allocated() {
    if (g_storage.values_page != nullptr) return true;
    g_storage.page_size = static_cast<size_t>(::sysconf(_SC_PAGESIZE));
    if (g_storage.page_size == 0) g_storage.page_size = 4096;

    auto map_one = []() -> void* {
        void* p = ::mmap(nullptr, g_storage.page_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (p == MAP_FAILED) ? nullptr : p;
    };
    g_storage.values_page = map_one();
    if (!g_storage.values_page) {
        RLOGE("F18 Vector D: mmap values_page failed errno=%d", errno);
        return false;
    }
    {
        // Same pid-seeded spacer trick as Vector A/C — randomises
        // the relative placement of the two pages.
        thread_local std::mt19937_64 rng(
            static_cast<uint64_t>(::getpid()) * 0xD1342543DE82EF95ull);
        const int spacers = static_cast<int>(rng() % 8);
        for (int i = 0; i < spacers; ++i) {
            void* spacer = ::mmap(nullptr, g_storage.page_size,
                                  PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                                  -1, 0);
            (void)spacer;
        }
    }
    g_storage.hash_page = map_one();
    if (!g_storage.hash_page) {
        ::munmap(g_storage.values_page, g_storage.page_size);
        g_storage.values_page = nullptr;
        RLOGE("F18 Vector D: mmap hash_page failed errno=%d", errno);
        return false;
    }
    std::memset(g_storage.values_page, 0, g_storage.page_size);
    std::memset(g_storage.hash_page, 0, g_storage.page_size);
    RLOGI("F18 Vector D: mmapped values=%p hash=%p (page=%zu)",
          g_storage.values_page, g_storage.hash_page, g_storage.page_size);
    return true;
}

bool unprotect_pages() {
    if (!g_storage.values_page || !g_storage.hash_page) return false;
    if (::mprotect(g_storage.values_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) return false;
    if (::mprotect(g_storage.hash_page, g_storage.page_size, PROT_READ | PROT_WRITE) != 0) {
        ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
        return false;
    }
    return true;
}

void reprotect_pages() {
    if (!g_storage.values_page || !g_storage.hash_page) return;
    ::mprotect(g_storage.values_page, g_storage.page_size, PROT_NONE);
    ::mprotect(g_storage.hash_page, g_storage.page_size, PROT_NONE);
}

void log_inline_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[4096];
    char values_perms[8] = "?";
    char hash_perms[8] = "?";
    const auto values_addr = reinterpret_cast<uintptr_t>(g_storage.values_page);
    const auto hash_addr = reinterpret_cast<uintptr_t>(g_storage.hash_page);
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (std::sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (values_addr >= start && values_addr < end) {
            std::strncpy(values_perms, perms, sizeof(values_perms) - 1);
        }
        if (hash_addr >= start && hash_addr < end) {
            std::strncpy(hash_perms, perms, sizeof(hash_perms) - 1);
        }
    }
    std::fclose(f);
    RLOGI("F18 Vector D audit: values@%p perms=%s, hash@%p perms=%s (expected ---p / ---p)",
          g_storage.values_page, values_perms, g_storage.hash_page, hash_perms);
}

bool recompute_and_verify_hash() {
    uint8_t recomputed[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, recomputed)) {
        RLOGW("F18 Vector D: sha256 backend unavailable; treating as intact");
        return true;
    }
    return std::memcmp(recomputed, g_storage.hash_page, sha::kDigestLen) == 0;
}

void store_hash_for_current_values() {
    uint8_t digest[sha::kDigestLen] = {};
    if (!sha::sha256(g_storage.values_page, kBaselineValuesBytes, digest)) {
        RLOGW("F18 Vector D: sha256 backend unavailable; storing zero hash");
    }
    std::memcpy(g_storage.hash_page, digest, sha::kDigestLen);
}

void copy_target_bytes(const void* addr, uint8_t out[kPrologueBytes]) {
    if (!addr) {
        std::memset(out, 0, kPrologueBytes);
        return;
    }
    std::memcpy(out, addr, kPrologueBytes);
}

void hex_dump(const uint8_t* bytes, size_t n, char* out, size_t out_cap) {
    static const char kHex[] = "0123456789abcdef";
    if (out_cap < n * 2 + 1) {
        if (out_cap > 0) out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[(bytes[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[bytes[i] & 0xF];
    }
    out[n * 2] = '\0';
}

}  // namespace

void initialize_inline_prologue() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    resolve_targets();
    if (!ensure_pages_allocated()) return;
    if (!unprotect_pages()) return;

    auto* values = static_cast<uint8_t*>(g_storage.values_page);
    for (size_t i = 0; i < kInlineMaxTargets; ++i) {
        uint8_t* slot = values + i * kPrologueBytes;
        copy_target_bytes(g_targets[i].addr, slot);
    }
    store_hash_for_current_values();
    // Log each captured prologue BEFORE reprotect so PROT_NONE
    // doesn't fault the read.
    char hexbuf[kPrologueBytes * 2 + 1] = {};
    for (size_t i = 0; i < kInlineMaxTargets; ++i) {
        if (!g_targets[i].symbol) continue;
        const uint8_t* slot = values + i * kPrologueBytes;
        hex_dump(slot, kPrologueBytes, hexbuf, sizeof(hexbuf));
        RLOGI("F18 Vector D snap[%zu] %-44s = %s",
              i, g_targets[i].symbol, hexbuf);
    }
    g_baseline_set.store(true, std::memory_order_release);
    reprotect_pages();
    RLOGI("F18 Vector D: snapshot captured at JNI_OnLoad");
}

size_t scan_inline_prologue(InlinePrologueScanEntry* out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_baseline_set.load(std::memory_order_acquire)) {
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }
    if (!ensure_pages_allocated()) return 0;
    if (!unprotect_pages()) return 0;

    const int api_int = ::android_get_device_api_level();
    auto* values = static_cast<uint8_t*>(g_storage.values_page);
    bool intact = recompute_and_verify_hash();

    const size_t n = (kInlineMaxTargets < out_capacity) ? kInlineMaxTargets : out_capacity;
    for (size_t i = 0; i < n; ++i) {
        InlinePrologueScanEntry& e = out[i];
        e.symbol = g_targets[i].symbol;
        e.addr = g_targets[i].addr;
        e.resolved = g_targets[i].resolved;
        e.drifted = false;
        e.baseline_known = false;
        e.baseline_mismatch = false;
        std::memset(e.live, 0, kPrologueBytes);
        std::memset(e.snapshot, 0, kPrologueBytes);
        if (!e.resolved) continue;

        copy_target_bytes(e.addr, e.live);
        const uint8_t* snap_slot = values + i * kPrologueBytes;
        if (intact) {
            std::memcpy(e.snapshot, snap_slot, kPrologueBytes);
            e.drifted = (std::memcmp(e.live, e.snapshot, kPrologueBytes) != 0);
        } else {
            // Baseline tampered → pretend snapshot equals live so
            // we don't false-positive the drift signal.
            std::memcpy(e.snapshot, e.live, kPrologueBytes);
            e.drifted = false;
        }

        if (const BaselineEntry* base = find_baseline(api_int, e.symbol)) {
            e.baseline_known = true;
            e.baseline_mismatch =
                (std::memcmp(e.live, base->bytes, kPrologueBytes) != 0);
        }
    }

    if (!intact) {
        // Recapture so the next scan has a fresh, intact baseline.
        for (size_t i = 0; i < n; ++i) {
            uint8_t* slot = values + i * kPrologueBytes;
            std::memcpy(slot, out[i].live, kPrologueBytes);
        }
        store_hash_for_current_values();
        RLOGW("F18 Vector D: baseline tampered — recaptured");
    }

    reprotect_pages();
    log_inline_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_inline_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

JNIEXPORT jobjectArray JNICALL extract_baseline_dump(JNIEnv* env) {
    // Dev-time only. Snapshot the current bytes for every
    // resolved target and return one string per slot. Format
    // matches the comment block above kBaselines so the
    // operator can paste rows in directly.
    if (g_resolved_count == 0) {
        // Lazy-init in case extraction is called before any
        // scan (i.e. the JNI bridge invoked it directly from
        // Kotlin without a prior detector run).
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_resolved_count == 0) {
            resolve_targets();
        }
    }
    const int api_int = ::android_get_device_api_level();
    jclass strCls = env->FindClass("java/lang/String");
    if (!strCls) return nullptr;
    jobjectArray out = env->NewObjectArray(static_cast<jsize>(kSymbolCount), strCls, nullptr);
    if (!out) return nullptr;
    char buf[256];
    char hexbuf[kPrologueBytes * 2 + 1] = {};
    for (size_t i = 0; i < kSymbolCount; ++i) {
        const ResolvedTarget& t = g_targets[i];
        if (t.resolved && t.addr) {
            uint8_t bytes[kPrologueBytes];
            copy_target_bytes(t.addr, bytes);
            hex_dump(bytes, kPrologueBytes, hexbuf, sizeof(hexbuf));
            std::snprintf(buf, sizeof(buf), "%s|%d|%s", t.symbol, api_int, hexbuf);
        } else {
            std::snprintf(buf, sizeof(buf), "%s|%d|missing", t.symbol, api_int);
        }
        jstring js = env->NewStringUTF(buf);
        if (!js) return nullptr;
        env->SetObjectArrayElement(out, static_cast<jsize>(i), js);
        env->DeleteLocalRef(js);
    }
    return out;
}

}  // namespace dicore::art_integrity
