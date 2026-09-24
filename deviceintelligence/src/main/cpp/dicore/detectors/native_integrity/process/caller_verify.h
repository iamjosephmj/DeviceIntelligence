#pragma once

// G7 — JNI return-address verification.
//
// Every JNI entry point we own should be called by the ART JNI
// dispatcher, whose code lives inside `libart.so`. If
// `__builtin_return_address(0)` at the top of one of our JNI
// functions resolves to something OUTSIDE libart's RX range,
// we're being trampolined: a hooker has installed a stub that
// wraps our entry point.
//
// The check itself is one address compare per entry; the cost
// is dominated by the (already-cheap) `range_map::classify`
// call.
//
// Per the rollout doc, G7 only instruments new entries in
// `native_integrity_jni.cpp` for now. Back-filling
// `art_integrity_jni.cpp` and `jni_bridge.cpp` is a follow-up
// (G7.5) tracked separately.

#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {

/** One captured violation. */
struct CallerViolation {
    char     function_name[96];
    uintptr_t return_address;
    uint8_t  return_class;     // dicore::native_integrity::Region as uint8_t
};

/**
 * Initialise the ring buffer + log the captured libart range.
 * Idempotent; safe to call from JNI_OnLoad. No-op if the range
 * map didn't capture libart (G7 silently disables in that case).
 */
void initialize_caller_verify();

/**
 * Records a violation iff [return_address] doesn't classify as
 * `Region::LIBART`. The string at [function_name] is copied
 * (truncated to fit the record buffer); pass `__func__`.
 *
 * Deduplicated by `(function_name, return_address)`: the same
 * hooked entry point + same trampoline return address only
 * produces ONE record across the lifetime of the process, even
 * if recorded thousands of times.
 */
void record_if_foreign(const char* function_name, void* return_address);

/**
 * Snapshot the current set of recorded violations. Writes up to
 * [capacity] records into [out] and returns the number written.
 *
 * Snapshot semantics — entries are NOT removed. Two concurrent
 * callers (e.g. a background pre-warm collect and an explicit
 * consumer collect both running on Dispatchers.IO) both see the
 * full set. The store is bounded by an internal cap; once full,
 * the oldest record is evicted FIFO at insert time.
 */
size_t snapshot(CallerViolation* out, size_t capacity);

}  // namespace dicore::native_integrity
