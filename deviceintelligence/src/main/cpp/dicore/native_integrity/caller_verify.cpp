#include "caller_verify.h"

#include "../log.h"
#include "range_map.h"

#include <atomic>
#include <cstring>
#include <mutex>

namespace dicore::native_integrity {

namespace {

// Snapshot store with insert-time deduplication and FIFO
// eviction at capacity. 256 distinct violations is enough that
// even a heavily-instrumented hooked process (every JNI entry
// point hooked by every framework on the device) doesn't churn
// out the early evidence.
//
// We hold a small mutex around the ring rather than going
// lock-free: the inner critical section is constant-time
// (memcmp + insert), JNI call rates are O(once-per-collect), and
// the simplicity buys us a clean dedup contract without an
// SPMC ring. Lock contention is therefore negligible while the
// dedup makes "snapshot returns the same violations on every
// call" a hard guarantee instead of a side effect.
constexpr size_t kRingSlots = 256;

CallerViolation g_ring[kRingSlots];
size_t g_head = 0;       // next slot to write (mod kRingSlots)
size_t g_count = 0;      // currently-occupied slots, capped at kRingSlots

std::mutex g_mutex;
std::atomic<bool> g_armed{false};

void copy_truncated(char* dest, size_t cap, const char* src) {
    if (cap == 0) return;
    if (src == nullptr) { dest[0] = '\0'; return; }
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < cap) {
        dest[i] = src[i];
        ++i;
    }
    dest[i] = '\0';
}

bool record_already_present_locked(const char* function_name, uintptr_t ra) {
    for (size_t i = 0; i < g_count; ++i) {
        const auto& rec = g_ring[i];
        if (rec.return_address != ra) continue;
        if (std::strncmp(rec.function_name, function_name,
                         sizeof(rec.function_name)) == 0) {
            return true;
        }
    }
    return false;
}

}  // namespace

void initialize_caller_verify() {
    if (g_armed.load(std::memory_order_acquire)) return;
    // libart's range is captured by `range_map::initialize_ranges`
    // at G1; we only need to confirm it's non-empty.
    const size_t libart_count = libart_range_count();
    if (libart_count == 0) {
        RLOGW("native_integrity: G7 init: libart range unavailable, caller verify disabled");
        return;
    }
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_head = 0;
        g_count = 0;
    }
    g_armed.store(true, std::memory_order_release);
    RLOGI(
        "native_integrity: G7 caller verify armed libart_ranges=%zu ring_slots=%zu",
        libart_count, kRingSlots
    );
}

void record_if_foreign(const char* function_name, void* return_address) {
    if (!g_armed.load(std::memory_order_acquire)) return;
    const Region cls = classify(return_address);
    if (cls == Region::LIBART) return;
    // Trusted ART-owned non-libart code: OAT trampolines that
    // dex2oat emits for the user app's NativeBridge stubs, and
    // JIT-compiled code in ART's code cache. Both legitimately
    // sit between Kotlin/Java and the JNI body and neither lives
    // in libart.so's static RX (the OAT lives in
    // /apex/.../boot-*.oat or /data/dalvik-cache/.../base.odex,
    // the JIT cache in [anon:dalvik-jit-code-cache] /
    // /memfd:jit-cache). Without this carve-out every JNI call
    // into libdicore on a stock device would surface as a
    // `native_caller_out_of_range` finding — see
    // `range_map::is_in_trusted_jit_or_oat` for the exact
    // trust list.
    if (is_in_trusted_jit_or_oat(return_address)) return;
    //
    //   - Inlining: clang may inline our entry point into the
    //     JNI thunk, in which case __builtin_return_address(0)
    //     resolves to the thunk caller (still libart). Mark the
    //     macro callers `__attribute__((noinline))` if
    //     inlining ever causes a regression here.
    const uintptr_t ra = reinterpret_cast<uintptr_t>(return_address);
    const char* fname = function_name ? function_name : "";

    std::lock_guard<std::mutex> lk(g_mutex);
    if (record_already_present_locked(fname, ra)) return;
    auto& rec = g_ring[g_head];
    copy_truncated(rec.function_name, sizeof(rec.function_name), fname);
    rec.return_address = ra;
    rec.return_class = static_cast<uint8_t>(cls);
    g_head = (g_head + 1) % kRingSlots;
    if (g_count < kRingSlots) ++g_count;
    // When g_count == kRingSlots and g_head wraps, the next
    // write will overwrite the oldest record; that's the FIFO
    // eviction the cap promises.
}

size_t snapshot(CallerViolation* out, size_t capacity) {
    if (out == nullptr || capacity == 0) return 0;
    std::lock_guard<std::mutex> lk(g_mutex);
    const size_t to_copy = (g_count < capacity) ? g_count : capacity;
    if (to_copy == 0) return 0;
    // Walk the ring oldest-first so the consumer sees a stable
    // chronological order. Oldest slot is at (head - count) when
    // !wrapped, otherwise at head when full and wrapped.
    const size_t start = (g_count < kRingSlots)
        ? 0
        : g_head;  // when full, head points at the oldest slot
    for (size_t i = 0; i < to_copy; ++i) {
        out[i] = g_ring[(start + i) % kRingSlots];
    }
    return to_copy;
}

}  // namespace dicore::native_integrity
