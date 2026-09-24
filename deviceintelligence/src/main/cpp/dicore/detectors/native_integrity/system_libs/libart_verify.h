#pragma once

// G10 — libart `.text` vs the pristine on-disk libart.so.
//
// WHY THIS EXISTS (measured, 2026-08-26, Pixel 6 Pro / Android 16 / arm64):
// Frida-Java's `cls.method.implementation = ...` does NOT always tamper the
// target ArtMethod. Against an already-native, already-compiled method
// (`Object#hashCode`) the ArtMethod is untouched — access_flags_, data_ and the
// quick entry are all byte-identical across the hook — so F18 vectors E and F
// have nothing to diff and the ART registry reports clean. What Frida patches
// instead is ART's dispatch itself: three assembly trampolines inside libart's
// own `.text`, each overwritten with Frida Gum's 16-byte absolute jump
// (`LDR x16, #8 ; BR x16 ; .quad target`):
//
//     art_quick_resolution_trampoline
//     art_quick_generic_jni_trampoline
//     art_quick_to_interpreter_bridge
//
// F18 Vector D (inline_prologue.cpp) already performs exactly the right check —
// a 16-byte prologue snapshot compared per scan — but it cannot cover these:
// its comment records that `art_quick_*` stubs are built `-fvisibility=hidden`,
// so they are absent from libart's `.dynsym` and neither `dlsym` nor the
// in-memory symtab walker can resolve them. (Confirmed on this build: the three
// symbols appear in neither `.dynsym` nor `.symtab`; the shipped libart.so has
// no `.symtab` at all.) Vector D's target list is therefore structurally unable
// to name them.
//
// So G10 does not try to name anything. It compares libart's whole executable
// segment against the same segment of the on-disk file, which needs no symbols
// and no per-ART-version offsets, and reports WHERE the bytes differ. The
// evidence is the patch site itself: its offset, the live bytes, the pristine
// bytes, and — when the live bytes form an absolute-jump stub — the branch
// target and whether it lands outside libart.
//
// FAIL-OPEN by construction: an unreadable file, a size skew between the mapped
// segment and the file (a legitimately different libart build), or a malformed
// ELF all yield kUnavailable, never a finding.
//
// COST: a `memcmp` of ~8.6MB against a file mapping held for the life of the
// process — ~2ms per scan on a Pixel 6 Pro, versus ~195ms for the SHA-256 this
// originally used. The compare short-circuits on the first differing byte, so a
// patched runtime costs less than a clean one, and the site walk runs only after
// a mismatch is already established.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dicore::native_integrity {

enum class LibArtTextStatus : uint8_t {
    kUnavailable = 0,   // could not locate/open/parse/size-match -> fail-open
    kOk = 1,            // live .text == on-disk .text
    kPatched = 2,       // live .text differs -> code patched after load
};

const char* libart_text_status_name(LibArtTextStatus s);

/** Bytes captured per patch site. 16 covers Frida's largest inline encoding. */
constexpr size_t kLibArtSiteBytes = 16;
/** Sites carried in the record. A hook engine patches a handful; the cap bounds the
 * token, and `sites_total` still reports how many were actually found. */
constexpr size_t kLibArtMaxSites = 4;

/** One contiguous run of differing bytes, with its decoded shape. */
struct LibArtPatchSite {
    uint64_t seg_offset = 0;        // offset within libart's executable segment
    uint64_t live_addr = 0;         // runtime address of the first differing byte
    uint32_t run_len = 0;           // length of the differing run
    uint8_t live[kLibArtSiteBytes] = {};
    uint8_t disk[kLibArtSiteBytes] = {};
    bool abs_jump_stub = false;     // live bytes are LDR x16/x17,#8 ; BR xN
    uint64_t target = 0;            // branch target when abs_jump_stub
    bool target_outside_libart = false;  // target escapes libart -> proof-positive
};

struct LibArtTextScan {
    LibArtTextStatus status = LibArtTextStatus::kUnavailable;
    uint64_t segment_bytes = 0;
    uint64_t diff_bytes = 0;        // total differing bytes across the segment
    size_t site_count = 0;          // sites recorded (capped at kLibArtMaxSites)
    size_t sites_total = 0;         // sites found, before the cap
    LibArtPatchSite sites[kLibArtMaxSites];
};

/**
 * Compare libart's live executable segment against the on-disk libart.so and,
 * on mismatch, locate the patch sites. Returns false only when the comparison
 * could not be made (status is then kUnavailable).
 */
bool scan_libart_text(LibArtTextScan* out);

/**
 * Findings for the orchestrator, `<kind>\x1f<severity>\x1f<description>\x1f<fields...>`.
 * Emits nothing when clean or unavailable.
 */
std::vector<std::string> libart_verdict_records();

}  // namespace dicore::native_integrity
