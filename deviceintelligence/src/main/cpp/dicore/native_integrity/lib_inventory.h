#pragma once

// G3 — loaded-library inventory + injected-anonymous-executable scan.
//
// Three findings power this layer:
//
//   - `injected_library`              — a `.so` is mapped into our
//     address space but isn't on the JNI_OnLoad baseline, isn't on
//     the build-time inventory, and isn't rooted in a canonical
//     AOSP system tree. This is the canonical Frida-gadget /
//     loaded-via-LD_PRELOAD signal (HIGH severity).
//
//   - `system_library_late_loaded`    — same as above, but the
//     path IS rooted in a canonical AOSP system tree (`/system/`,
//     `/system_ext/`, `/product/`, `/odm/`, `/vendor/`, `/apex/`,
//     `/data/dalvik-cache/`). Common on emulators and OEMs that
//     defer vendor library init past JNI_OnLoad. Surfaced at
//     MEDIUM severity for forensic completeness without producing
//     dozens of false-positive HIGH findings on a clean emulator.
//     System partitions are dm-verity-protected, so an actual
//     attacker writing here is independently caught by
//     `runtime.root` / `integrity.bootloader` / `attestation.key`.
//
//   - `injected_anonymous_executable` — a memory range is mapped
//     RX (or RWX) and isn't a recognised system mapping (JIT
//     cache / linker bookkeeping). This is the canonical
//     in-process JIT-of-a-hooker / staged-shellcode signal
//     (HIGH severity).
//
// The build-time inventory comes from
// `Fingerprint.nativeLibInventoryByAbi[currentAbi]` and is
// installed once per process via `set_expected_so_inventory()`.

#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {

/**
 * Replaces the allowlisted `.so` filename set with [filenames].
 * `filenames` is a non-owning array of `count` C-string pointers
 * that MUST remain valid for the duration of the call (this
 * function copies them into internal storage). Empty `count`
 * disables the inventory check (used when the v1 fingerprint has
 * no per-ABI data).
 *
 * Idempotent — calls after the first overwrite the previous
 * inventory. Thread-safe.
 */
void set_expected_so_inventory(const char* const* filenames, size_t count);

/** One inventory finding. */
struct InventoryRecord {
    enum class Kind : uint8_t {
        INJECTED_LIBRARY = 0,
        INJECTED_ANON_EXEC = 1,
        // A library that wasn't in the JNI_OnLoad baseline AND wasn't on the
        // build-time inventory, but whose path is rooted in a canonical
        // AOSP system tree (`/system/`, `/system_ext/`, `/product/`, `/odm/`,
        // `/vendor/`, `/apex/`, `/data/dalvik-cache/`). Common on emulators
        // and OEMs that lazy-load vendor GL / HAL implementations after our
        // baseline snapshot — flagged as MEDIUM rather than HIGH because
        // those partitions are read-only and require root + remount to
        // tamper with, and other detectors (`runtime.root`,
        // `integrity.bootloader`, `attestation.key`) catch that case
        // independently.
        SYSTEM_LIB_LATE_LOADED = 2,
    };
    Kind kind;
    char path[512];     // filename for INJECTED_LIBRARY / SYSTEM_LIB_LATE_LOADED, address-range string for ANON
    char perms[8];      // "r-xp" / "rwxp" / etc; "" for INJECTED_LIBRARY / SYSTEM_LIB_LATE_LOADED
};

/**
 * Re-scans `dl_iterate_phdr` and `/proc/self/maps`, comparing
 * each loaded library against the allowlist (build-time inventory
 * + system-path prefixes), and each executable mapping against
 * the known-good labels (libdl bookkeeping, JIT cache, OAT files,
 * any allowlisted `.so`).
 *
 * Writes up to [capacity] records into [out] and returns the
 * number written. The native side enforces the cap so a
 * pathological device doesn't blow up the JNI return array.
 */
size_t scan_loaded_libraries(InventoryRecord* out, size_t capacity);

}  // namespace dicore::native_integrity
