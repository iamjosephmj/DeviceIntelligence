#pragma once

// G3 — loaded-library inventory + injected-anonymous-executable scan.
//
// Two findings power this layer:
//
//   - `injected_library`              — a `.so` is mapped into our
//     address space but isn't on the build-time inventory AND
//     isn't backed by a path we recognise as system code
//     (`/system/`, `/vendor/`, `/apex/`, `/data/dalvik-cache/`).
//     This is the canonical Frida-gadget / loaded-via-LD_PRELOAD
//     signal.
//
//   - `injected_anonymous_executable` — a memory range is mapped
//     RX (or RWX) and isn't a recognised system mapping (JIT
//     cache / linker bookkeeping). This is the canonical
//     in-process JIT-of-a-hooker / staged-shellcode signal.
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
    };
    Kind kind;
    char path[512];     // filename for INJECTED_LIBRARY, address-range string for ANON
    char perms[8];      // "r-xp" / "rwxp" / etc; "" for INJECTED_LIBRARY
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
