#pragma once

// Own-image resolution for digest-bound string keys (plan task A1) and any
// future consumer that needs "the exec segment of the library this code is
// linked into".
//
// The INTEL_0059 probe locates its segment via dl_iterate_phdr + a soname
// suffix (native_integrity/shared/module_text.h). That shape is unusable
// here for two reasons:
//   1. The strenc decryptor runs from init_array constructors — the dynamic
//      loader may hold its locks there, and dl_iterate_phdr/dladdr/dlopen
//      re-enter it. The resolution below never calls into the loader: it
//      reads /proc/self/maps through the raw-syscall svc layer (B3) and
//      parses the ELF headers directly from our mapped first page.
//   2. Address-based self-identification (which mapping contains this very
//      function) works for any image name — libdicore.so on device, the
//      obf-check fixture executable on the host — no name coupling.
//
// Hash inputs are the exec segment's FIRST PAGE (min(4096, p_filesz)), the
// same file bytes the loader maps (the exec segment carries no dynamic
// relocations), so build-time (tools/native/dicore-bind-strkeys.py over the
// linked ELF) and runtime digests are byte-equal on an untampered image.
// Kept in lock-step with gen-dicore-text-digest.py's segment selection.

#include <cstddef>
#include <cstdint>

namespace dicore::platform::own_image {

// The digest covers at most the first page of the exec segment.
constexpr size_t kKeyPage = 4096;

/** Fold the first 128 bits of a SHA-256 into u64 key material:
 *  le64(d[0..8]) ^ le64(d[8..16]). Pure. */
uint64_t fold_digest128(const uint8_t sha[32]);

/** Digest-bound per-string key: key0 XOR fold_digest128(digest). Pure.
 *  key0 is the pass-time seed-only key; the digest part is never stored in
 *  the binary — it is recomputed from the live image at load. */
uint64_t derive_text_key(uint64_t key0, const uint8_t sha[32]);

/** The byte range the key digest covers, located in an in-memory ELF image
 *  (our live mapping, an mmap'd file, a synthetic test buffer). Pure.
 *
 *  Contract: [image, image_len) must cover the ELF header AND the program
 *  header table (for our images: the first mapped page). The described
 *  digest range itself may lie OUTSIDE that window — the live path reads it
 *  from a different mapping, whole-file callers check offset+len themselves.
 *  (This is why this is not shared/elf_segment's find_exec_segment: that one
 *  bounds-checks the segment inside the buffer — right for on-disk files,
 *  wrong for a header-only window.) */
struct ExecPage {
    uintptr_t vaddr;   // link-time vaddr of the digest range
    uint64_t offset;   // file offset of the digest range
    size_t len;        // min(kKeyPage, p_filesz)
};
bool exec_page(const uint8_t* image, size_t image_len, ExecPage* out);

/** The resolved own image: everything exec_digest32 needs, exposed for
 *  host tests that feed real mmap'd layouts (extracted file, zip-embedded
 *  whole-entry, linker-split apk mappings) through simulated or real maps
 *  buffers without going through /proc themselves. */
struct ResolvedExec {
    const uint8_t* base;  // derived address of our ELF header (e_phoff anchor)
    ExecPage ep;          // the digest range, from base's own phdr table
    uintptr_t v0;         // first PT_LOAD vaddr (the load-bias anchor)
    const uint8_t* page;  // address of the digest range — readable on success
};

/** Resolve the exec page of the image that owns `marker`, from a
 *  /proc/self/maps-format buffer (the live path passes its raw-syscall read;
 *  tests may pass real or simulated maps text over a real mmap'd layout).
 *
 *  Works for every loader layout this code ships under:
 *    - extracted .so (plain file mappings; the first PT_LOAD's mapping has
 *      file offset 0 — the only case the original "off-0 mapping" scan saw),
 *    - zip-embedded (useLegacyPackaging=false): PT_LOADs mapped straight out
 *      of base.apk — maps entries carry the APK path and ABSOLUTE apk file
 *      offsets, and no off-0 mapping of the library exists. The base is
 *  derived from the marker's own mapping: for every PT_LOAD mapping of one
 *  image, (mapping start − mapping file offset) is the same constant, so
 *  under the hypothesis "candidate mapping j is the first PT_LOAD's",
 *      base = S_marker − (F_marker − F_j)
 *  (the zip-entry offset cancels in the difference). Every candidate is
 *  verified fault-safely (process_vm_readv against self — EFAULT, never
 *  SIGSEGV): ELF magic at the derived base itself, a walkable PF_X phdr,
 *  and the offset identity above; a candidate that is the marker's own
 *  mapping must instead contain the whole ELF (whole-entry zip layout).
 *  Nothing verifies → false. No guessing, no faulting: a tampered or
 *  unresolvable layout fails closed (keys degrade, callers stay up). */
bool resolve_exec_page(const char* maps, size_t maps_len, uintptr_t marker,
                       ResolvedExec* out);

/** SHA-256 over our own live exec page (raw_sha256 — no libcrypto, loader-
 *  safe). False only when /proc/self/maps is unreadable or our image cannot
 *  be resolved; callers degrade to unbound keys. The resolution (maps read
 *  + parse + digest) is cached per thread: a release image's ~71 strenc
 *  ctors all call this, and re-reading /proc 71 times per load buys
 *  nothing (each thread resolves once). */
bool exec_digest32(uint8_t out[32]);

/** fold_digest128(exec_digest32()) — the runtime half of every bound key. */
bool exec_key_material(uint64_t* out);

}  // namespace dicore::platform::own_image

/** C ABI for the obfuscator pass's emitted ctor (the obfuscating toolchain declares and
 *  calls this by name; it lives here so every TU's dicore.strdec ctor links
 * against the one definition in libdicore). Returns 0 on resolution
 * failure — bound strings then decrypt to garbage; the bind tool only binds
 * images whose runtime can resolve (see task report). */
extern "C" uint64_t dicore_exec_text_key64();
