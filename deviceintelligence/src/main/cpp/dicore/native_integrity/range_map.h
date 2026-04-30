#pragma once

// Native-integrity range classifier. Backs every layer in
// NATIVE_INTEGRITY_DESIGN.md: the `.text` self-integrity check
// (G2), the injected-library detector (G3), the GOT verifier (G4),
// and the JNI return-address check (G7) all need to answer the
// same question for an arbitrary code pointer:
//
//     "is this address inside libc / libm / libdl / libart /
//      libdicore — or somewhere else?"
//
// The "somewhere else" bucket (`Region::UNKNOWN`) is where every
// real attack signal lives: a pointer inside `libdicore.so`'s GOT
// that resolves into attacker-allocated memory, a JNI return
// address that landed in a Frida trampoline page, a `.text` byte
// patched by `mprotect+memcpy`.
//
// We sit alongside `art_integrity::ranges` rather than reusing it
// because they answer different questions. `art_integrity::ranges`
// classifies into `libart / boot_oat / jit_cache / oat_other` —
// useful for vector A's "did this ArtMethod escape ART?" but it
// has no notion of libc vs libdl, and no entry for libdicore at
// all. Sharing the dl_iterate_phdr walk would have created a
// cyclic include between the two subsystems for negligible saving;
// the second walk costs <1 ms and only ever runs once per process.

#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {

/**
 * Coarse classification of any pointer we might hold. Members are
 * stable wire constants — `region_name()` exposes them as the
 * `details.live_classification` / `details.snapshot_classification`
 * fields on the findings emitted by G4 / G7.
 */
enum class Region : uint8_t {
    UNKNOWN = 0,
    LIBC = 1,
    LIBM = 2,
    LIBDL = 3,
    LIBART = 4,
    LIBDICORE = 5,
    OTHER_SYSTEM = 6,  // /system/ /vendor/ /apex/ — known-good but unnamed
};

/** Stable forensic name for a [Region]; used in finding details. */
const char* region_name(Region r);

/**
 * Builds the range set on first call by walking `dl_iterate_phdr`.
 * Subsequent calls are no-ops and return the same total. Returns
 * the sum of all captured RX-range counts (libc + libm + libdl +
 * libart + libdicore + other_system).
 *
 * Designed to be called from `JNI_OnLoad` BEFORE any user-space
 * hook has a realistic chance of being installed — the snapshot
 * captures the loader's view of the world at process start, which
 * is the trust anchor for everything that follows.
 */
size_t initialize_ranges();

/**
 * Classifies [addr] against the captured ranges. UNKNOWN means
 * the pointer escaped every recognised range; that's the
 * actionable signal.
 *
 * Note: only **executable (RX) PT_LOAD ranges** are considered.
 * A pointer into libdicore's `.data` (RW) or `.rodata` (RO)
 * segment will return UNKNOWN. That is the right call for G7
 * (which is asking "is this a JNI return address inside libart's
 * code?") but the wrong call for G4 (which is asking "is this
 * GOT pointer a recognisable address at all?"). G4 must use
 * [is_in_known_image] instead of `classify(...) != UNKNOWN`.
 */
Region classify(const void* addr);

/**
 * Whole-image equivalent of [classify]: returns true iff [addr]
 * lies inside ANY PT_LOAD (RX, RW, or RO) of any image we
 * iterated at `JNI_OnLoad` time. Used by G4 to decide whether a
 * GOT entry's value is "out of range".
 *
 * Why we need a separate predicate: GOT slots legitimately point
 * not just to functions in other libraries (RX) but also to
 * extern data in those libraries (RO/RW), and to libdicore's own
 * `.data` / `.data.rel.ro` / `.bss` (PIC self-references via
 * `R_AARCH64_RELATIVE`). [classify] would return UNKNOWN for all
 * of those and false-positive every clean device.
 */
bool is_in_known_image(const void* addr);

/**
 * Returns true iff [addr] is a JNI return address that should
 * be considered legitimate ART-owned code. Delegates to
 * `baseline::is_address_trusted_via_baseline`, which trusts:
 *
 *  - Any RX mapping that was already present in the process at
 *    `JNI_OnLoad` time (boot OAT, libart.so, the framework
 *    OAT/dex2oat output, the JIT code cache pages already
 *    allocated by the time we initialised).
 *  - Any current RX mapping whose label or parent directory
 *    matches a baseline mapping (the JIT cache grew, OAT was
 *    recompiled in-place, a sibling library loaded from the
 *    same partition).
 *
 * This wrapper exists to keep the G7 caller-verify call site
 * stable; the actual policy lives in `baseline.cpp`. Replaces
 * the previous implementation that consulted hardcoded
 * `/apex/`, `/system_ext/`, `/product/`, `[anon:jit-cache]`,
 * etc. allowlists — all of which had to be patched whenever a
 * new OEM partition appeared or a new kernel renamed a label.
 */
bool is_in_trusted_jit_or_oat(const void* addr);

/**
 * Captured load address + RX extents of `libdicore.so` itself.
 * Returned as the trio (base_addr, rx_start, rx_end). Used by
 * `text_verify` (G2) and `got_verify` (G4) to locate our own ELF
 * headers without re-walking `dl_iterate_phdr` (which could be
 * hooked between OnLoad and now).
 *
 * All three are zero if libdicore couldn't be located at OnLoad
 * time — the dependent layers degrade gracefully in that case.
 */
struct LibdicoreLayout {
    uintptr_t base_addr;
    uintptr_t rx_start;
    uintptr_t rx_end;
};
LibdicoreLayout libdicore_layout();

/**
 * Returns the on-disk path the loader reported for `libdicore.so`
 * (e.g. `/data/app/~~xxx==/com.example-...=/lib/arm64-v8a/libdicore.so`).
 * Used by `got_verify` (G4) to mmap the file and read its section
 * headers, which usually aren't loaded into memory by the linker.
 *
 * Returns nullptr if the path wasn't captured at OnLoad (e.g.
 * the dl iteration didn't surface libdicore — extremely rare,
 * usually means we're running in some non-standard linker
 * namespace and G4 will degrade silently).
 */
const char* libdicore_path();

/** Diagnostic counters for the G1 CTF logging. */
size_t libc_range_count();
size_t libm_range_count();
size_t libdl_range_count();
size_t libart_range_count();
size_t libdicore_range_count();
size_t other_system_range_count();

}  // namespace dicore::native_integrity
