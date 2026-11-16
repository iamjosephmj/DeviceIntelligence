#include "dicore/detectors/art_integrity/checks/inline_prologue.h"

#include "dicore/platform/log.h"
#include "dicore/platform/safe_text_read.h"
#include "dicore/platform/svc_io.h"
#include "dicore/crypto/sha256.h"
#include "dicore/detectors/art_integrity/runtime/libart_symtab.h"

#include <android/api-level.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

#include "dicore/platform/protected_store.h"

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
// Empty by default fleet-wide (see `kBaselines` rationale below).
// Symbols + APIs without a row are scanned for drift but skipped
// for baseline-mismatch — the absence of an embedded baseline
// is NOT a finding, just a coverage gap.
//
// To populate for an internal fleet:
//   1. Run `NativeBridge.artIntegrityExtractPrologueBaseline()`
//      on every clean device variant in your sample.
//   2. The returned strings are `"<symbol>|<api_int>|<hex_bytes>"`.
//   3. Only embed rows whose 16-byte prefix is byte-identical
//      across EVERY sampled device for that (api_int, symbol).
//      Rows that vary across builds re-introduce false positives.
// ----------------------------------------------------------------
struct BaselineEntry {
    int api_int;
    const char* symbol;
    uint8_t bytes[kPrologueBytes];
};

// Per-arch baseline tables.
//
// Intentionally empty for every arch by default. Earlier versions
// embedded API-36 arm64 rows harvested from a small Pixel test
// fleet (Tensor G4 + Tensor G1), but field telemetry showed those
// rows produced a steady stream of MEDIUM `baseline_mismatch`
// false positives on benign devices: prologue bytes legitimately
// vary across clean libart builds at the same API level, even on
// the same arch. The drivers of that variance are mundane (stack
// frame size immediates, PIC offsets baked into adrp/ldr pairs,
// register-allocation and inlining differences across AOSP revs).
//
// Rather than chase a per-libart-build harvest pipeline, the
// detector now relies on Vector D's drift check (live vs the
// JNI_OnLoad snapshot we capture in-process) for real-hook
// detection. Drift compares the device against itself, so it is
// immune to build skew and is what actually catches runtime
// patches by Frida / Xposed / LSPosed. The "patched before our
// JNI_OnLoad ran" attack the embedded table was meant to backstop
// is independently caught by `injected_library`,
// `hook_framework_present`, the GOT and `.text` integrity layers,
// the stack and caller-verification layers, and ART Vectors A/C.
//
// To re-enable a build-time baseline (e.g. for an internal fleet
// where you control the libart variant population), fill
// kBaselines with rows in the format `{api_int, symbol, bytes}`
// harvested via `NativeBridge.artIntegrityExtractPrologueBaseline()`.
// Only embed rows where EVERY clean device in your sample fleet
// produces the same 16-byte prefix, otherwise the false-positive
// pattern returns.
const BaselineEntry* const kBaselines = nullptr;
constexpr size_t kBaselineCount = 0;

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

void resolve_targets() {
    if (!libart_symtab_ready()) {
        RLOGW("F18 Vector D: libart symtab walker failed (no PT_DYNAMIC?)");
        return;
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
ProtectedStore g_store;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;
std::atomic<bool> g_last_intact{true};

constexpr size_t kBaselineValuesBytes = kInlineMaxTargets * kPrologueBytes;

void log_inline_protection_audit() {
    static std::atomic<bool> already_logged{false};
    bool expected = false;
    if (!already_logged.compare_exchange_strong(expected, true)) return;
    std::string maps;
    if (!svc::read_file("/proc/self/maps", &maps)) return;
    char values_perms[8] = "?";
    char hash_perms[8] = "?";
    const auto values_addr = reinterpret_cast<uintptr_t>(g_store.values_page());
    const auto hash_addr = reinterpret_cast<uintptr_t>(g_store.hash_page());
    svc::LineCursor cur(maps);
    std::string line;
    while (cur.next(&line)) {
        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        if (std::sscanf(line.c_str(), "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (values_addr >= start && values_addr < end) {
            std::strncpy(values_perms, perms, sizeof(values_perms) - 1);
        }
        if (hash_addr >= start && hash_addr < end) {
            std::strncpy(hash_perms, perms, sizeof(hash_perms) - 1);
        }
    }
    RLOGI("F18 Vector D audit: values@%p perms=%s, hash@%p perms=%s (expected ---p / ---p)",
          g_store.values_page(), values_perms, g_store.hash_page(), hash_perms);
}

void copy_target_bytes(const void* addr, uint8_t out[kPrologueBytes]) {
    if (!addr) {
        std::memset(out, 0, kPrologueBytes);
        return;
    }
    // NOT memcpy: on Android 10+ arm64 libart's .text is mapped execute-only, and a
    // plain deref here died with SIGSEGV/SEGV_ACCERR inside JNI_OnLoad. safe_read_code
    // goes via /proc/self/mem, which reads through the protection. Zero-fill on
    // failure keeps the old contract for an unresolvable target: callers already
    // treat an all-zero prologue as "nothing to compare".
    if (!platform::safe_read_code(addr, out, kPrologueBytes)) {
        std::memset(out, 0, kPrologueBytes);
    }
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
    if (!g_store.init(kBaselineValuesBytes)) return;
    if (!g_store.unprotect()) return;

    auto* values = static_cast<uint8_t*>(g_store.values());
    for (size_t i = 0; i < kInlineMaxTargets; ++i) {
        uint8_t* slot = values + i * kPrologueBytes;
        copy_target_bytes(g_targets[i].addr, slot);
    }
    g_store.rehash();
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
    g_store.reprotect();
    RLOGI("F18 Vector D: snapshot captured at JNI_OnLoad");
}

size_t scan_inline_prologue(InlinePrologueScanEntry* out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_baseline_set.load(std::memory_order_acquire)) {
        g_last_intact.store(true, std::memory_order_release);
        return 0;
    }
    if (!g_store.init(kBaselineValuesBytes)) return 0;
    if (!g_store.unprotect()) return 0;

    const int api_int = ::android_get_device_api_level();
    auto* values = static_cast<uint8_t*>(g_store.values());
    bool intact = g_store.intact();

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
        g_store.rehash();
        RLOGW("F18 Vector D: baseline tampered — recaptured");
    }

    g_store.reprotect();
    log_inline_protection_audit();
    g_last_intact.store(intact, std::memory_order_release);
    return n;
}

bool last_inline_baseline_intact() {
    return g_last_intact.load(std::memory_order_acquire);
}

}  // namespace dicore::art_integrity
