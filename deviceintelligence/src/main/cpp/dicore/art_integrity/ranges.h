#pragma once

// F18 — process-address-space range resolver and classifier.
//
// Vector A (and later vectors) need to answer one question for any
// arbitrary address: "is this currently inside `libart.so`'s
// executable segment, inside a boot OAT file, inside the JIT
// cache, or somewhere else?" That last bucket is the one that
// matters: an `ArtMethod` whose entry pointer escapes the known
// ART memory regions is by definition pointing at a hook stub.
//
// The resolver is built once at first use and cached. ASLR moves
// every region per-process, so values must be read at runtime;
// hard-coding any of them would break on the very next reboot.
//
// Sources:
//   - libart.so RX: `dl_iterate_phdr` over the loader's view of
//     loaded ELFs, picking the segments with `PF_X`.
//   - boot OAT RX: `/proc/self/maps` lines whose pathname ends in
//     `.oat` / `.art` with executable permission, restricted to
//     the canonical boot-image paths (`/apex/com.android.art/...`,
//     `/system/framework/...`, `/data/dalvik-cache/.../boot*.oat`).
//   - JIT cache: `/proc/self/maps` anonymous executable mappings
//     whose label contains "jit" (the kernel labels are
//     `[anon:jit-code-cache]` / `[anon:dalvik-jit-code-cache]`,
//     spelled differently across Android versions).

#include <cstddef>
#include <cstdint>

namespace dicore::art_integrity {

enum class Classification : uint8_t {
    UNKNOWN = 0,
    IN_LIBART = 1,
    IN_BOOT_OAT = 2,
    IN_JIT_CACHE = 3,
    IN_OAT_OTHER = 4,  // other oat/art files (apps, secondary dex)
};

/**
 * Stable forensic name for a [Classification], surfaced into
 * findings so backends can pivot on it.
 */
const char* classification_name(Classification c);

/**
 * Builds the range set on first call by scanning loader state and
 * `/proc/self/maps`. Subsequent calls return the cached result
 * without re-scanning. Returns the number of region entries
 * captured (libart_rx + boot_oat_rx + jit_cache + oat_other_rx).
 *
 * Returns 0 if the scan failed completely (e.g. /proc/self/maps
 * unreadable). Callers can treat 0 as "ranges unavailable" and
 * skip downstream classification rather than crashing.
 */
size_t initialize_ranges();

/**
 * Classifies [addr] as one of the known ART memory regions.
 * Returns `UNKNOWN` for anything outside libart, boot OAT, JIT
 * cache, or other OAT files — that bucket is the high-signal
 * one for Vector A.
 */
Classification classify(const void* addr);

/** Diagnostic counters for the M3 CTF logging. */
size_t libart_range_count();
size_t boot_oat_range_count();
size_t jit_cache_range_count();
size_t other_oat_range_count();

}  // namespace dicore::art_integrity
