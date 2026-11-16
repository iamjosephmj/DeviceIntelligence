#pragma once

// G3/G7 trust baseline — captures the process's "loaded image"
// view at JNI_OnLoad time and exposes that snapshot as the trust
// boundary for every later integrity scan.
//
// The architectural shift this header enables:
//
//   BEFORE: G3 ("is this loaded library a hooker?") and G7 ("is
//   this JNI return address legitimate?") consulted hardcoded
//   path/label allowlists baked into the source. Every new OEM
//   partition (`/system_ext/`, `/product/`, `/odm/`) and every
//   new kernel-renamed anonymous label (`[anon_shmem:dalvik-...]`)
//   forced a code update or false-positived production devices.
//
//   AFTER: at JNI_OnLoad we snapshot the ground truth — every
//   library the loader has placed in our address space, every
//   executable mapping in /proc/self/maps, the directory each
//   came from, and our own app's lib directory. Anything in that
//   snapshot is trusted forever in this process. Anything that
//   appears later is judged against the snapshot's *directories*
//   and *anonymous labels* — i.e., if zygote loaded any library
//   from `/foo_partition/lib64/` at start, then a later load of
//   another library from `/foo_partition/lib64/` is trusted by
//   inheritance, not because we hardcoded the partition name.
//
// This makes G3 and G7 self-adapting to any OEM, any Android
// version, and any kernel that renames anonymous mapping labels.
// The only price we pay is: anything injected into our process
// BEFORE JNI_OnLoad runs becomes part of the trust boundary.
// G2 (.text hashing) and G5 (StackGuard) still fire the moment
// such a preloaded library does anything observable, so that
// trade is acceptable for an anti-hooking tool whose threat model
// is "active hooking from any source", not "passive presence of
// known-bad code".

#include <cstddef>
#include <cstdint>

namespace dicore::native_integrity {

/**
 * Capture the baseline. Walks `dl_iterate_phdr` for the loaded
 * library set and `/proc/self/maps` for the executable mapping
 * set, plus derives our own app's lib directory from libdicore's
 * loader-reported path.
 *
 * Idempotent (subsequent calls are no-ops). Safe to call from
 * `JNI_OnLoad` via `module::initialize`; both range_map and
 * baseline must be initialised before any G3/G7 scan runs.
 *
 * Returns the total number of baseline entries captured (sum of
 * libraries + RX mappings). Zero is plausible only on the unusual
 * device where `/proc/self/maps` is unreadable AND
 * dl_iterate_phdr walked nothing — both layers degrade silently.
 */
size_t initialize_baseline();

/**
 * Returns true iff [path] is a library that was loaded into the
 * process before [initialize_baseline] ran, OR sits in a
 * directory that contained at least one such library, OR sits
 * under our own app's lib directory, OR sits under any
 * directory declared at runtime via [add_trusted_directory].
 *
 * The directory-inheritance rule (`/foo/bar/libnew.so` is
 * trusted if `/foo/bar/libold.so` was in baseline) is the
 * mechanism that auto-allowlists OEM partitions on first
 * encounter without ever naming them in code.
 */
bool is_library_in_baseline(const char* path);

/**
 * Append a runtime-discovered trusted directory. Future
 * [is_library_in_baseline] / [is_address_trusted_via_baseline]
 * calls treat any path/mapping under [path] (or [path]/) as
 * trusted by directory inheritance.
 *
 * Intended use: the Kotlin layer calls this with
 * `context.applicationInfo.dataDir` (and the symlinked
 * `/data/data/<pkg>` form) on first collect, so legitimate
 * lazy-loaded `.so`s the consumer app dlopen()s out of its
 * own private data area aren't flagged as injected libraries.
 *
 * Safe to call concurrently with scans; reads use a snapshot
 * of the runtime list under a small lock.
 *
 * Threat-model rationale: only our own app process (or root)
 * can write under `/data/data/<our_pkg>/`. Frida and LSPosed
 * never use that path — Frida injects from `/data/local/tmp/`
 * or `/memfd:`, LSPosed uses zygisk paths. So trusting the
 * app's data dir eliminates the lazy-load false-positive class
 * without weakening hooker detection.
 */
void add_trusted_directory(const char* path);

/**
 * Returns true iff [addr] lies inside any RX mapping captured
 * by the baseline — file-backed OR label-bearing anonymous.
 */
bool is_address_in_baseline_rx(uintptr_t addr);

/**
 * Returns true iff [label] (a `[anon:...]` or
 * `[anon_shmem:...]` mapping label) appeared in the baseline,
 * OR if [path] is under a directory that contained at least one
 * baseline RX file-backed mapping.
 *
 * For G3 anonymous-mapping handling: an anonymous executable
 * mapping that wasn't in the baseline but carries a label that
 * WAS (e.g., the JIT cache grew and got a new mapping with the
 * same `[anon:dalvik-jit-code-cache]` label) is trusted by
 * label inheritance.
 */
bool is_anon_label_in_baseline(const char* label, size_t label_len);

/**
 * "Trusted JIT-or-OAT" check for G7. Resolves [addr] to a
 * current /proc/self/maps entry; trusted iff:
 *   - addr is inside a baseline RX mapping, OR
 *   - addr is inside a current RX mapping whose path lives in
 *     a directory that contained baseline RX mappings, OR
 *   - addr is inside a current RX anonymous mapping whose label
 *     was in the baseline.
 *
 * Drop-in replacement for the previous
 * `range_map::is_in_trusted_jit_or_oat` (which used hardcoded
 * `/apex/`, `/system/framework/`, `[anon:jit-cache]` etc lists).
 */
bool is_address_trusted_via_baseline(uintptr_t addr);

}  // namespace dicore::native_integrity
