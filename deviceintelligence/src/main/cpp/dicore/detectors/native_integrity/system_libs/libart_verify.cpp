#include "dicore/detectors/native_integrity/system_libs/libart_verify.h"

#include "dicore/detectors/native_integrity/shared/module_text.h"
#include "dicore/orchestrator/record_util.h"
#include "dicore/platform/log.h"
#include "dicore/platform/safe_text_read.h"

#include <vector>

#include <cstdio>
#include <cstring>

namespace dicore::native_integrity {

namespace {

#if defined(__LP64__)
constexpr const char* kLibArtFallback = "/apex/com.android.art/lib64/libart.so";
#else
constexpr const char* kLibArtFallback = "/apex/com.android.art/lib/libart.so";
#endif

// Two differing runs closer than this are one patch site: Frida's stub is a
// 16-byte unit whose middle bytes can coincidentally match the original.
constexpr uint64_t kSiteGap = 16;

std::string hex(const uint8_t* b, size_t n) {
    static const char kH[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += kH[b[i] >> 4]; s += kH[b[i] & 0xF]; }
    return s;
}

std::string append_field(std::string r, const std::string& f) { r += kFS; r += f; return r; }

// arm64 absolute-jump stub: `LDR <Xt>, #8` followed by `BR <Xt>` — the literal
// eight bytes on is the branch target. Frida Gum emits x16/x17, but other
// engines pick other scratch registers, so the register is read from the
// encoding rather than hard-coded; requiring the BR to use the SAME register as
// the LDR keeps this an exact shape match, not an "any load near any branch"
// heuristic. A legitimately-compiled function entry is stack setup or a BTI
// landing pad, never this.
bool decode_abs_jump(const uint8_t* p, uint64_t* out_target) {
    uint32_t w0 = 0, w1 = 0;
    std::memcpy(&w0, p, 4);
    std::memcpy(&w1, p + 4, 4);
    // LDR <Xt>, #8  — 64-bit literal load, imm19 == 2 (the .quad sits two words on).
    if ((w0 & 0xFF000000u) != 0x58000000u) return false;
    if (((w0 >> 5) & 0x7FFFFu) != 2u) return false;
    const uint32_t rt = w0 & 0x1Fu;
    // BR <Xn> with n == t. Requiring the SAME register is what keeps this a
    // trampoline match rather than an "any load near any branch" heuristic.
    if ((w1 & 0xFFFFFC1Fu) != 0xD61F0000u) return false;
    if (((w1 >> 5) & 0x1Fu) != rt) return false;
    uint64_t t = 0;
    std::memcpy(&t, p + 8, 8);
    *out_target = t;
    return true;
}

}  // namespace

const char* libart_text_status_name(LibArtTextStatus s) {
    switch (s) {
        case LibArtTextStatus::kOk:          return "ok";
        case LibArtTextStatus::kPatched:     return "patched";
        case LibArtTextStatus::kUnavailable: return "unavailable";
    }
    return "unavailable";
}

bool scan_libart_text(LibArtTextScan* out) {
    if (!out) return false;
    *out = LibArtTextScan{};

    LiveExecSeg live;
    if (!find_live_exec_seg("libart.so", &live)) return false;

    const char* path = (live.name[0] == '/') ? live.name : kLibArtFallback;

    // The pristine copy is mapped ONCE and kept for the life of the process.
    // Two reasons. It is what makes the steady-state check a `memcmp` instead of
    // a SHA-256 of ~8.6MB (measured on a Pixel 6 Pro: ~195ms per scan hashing,
    // ~2ms comparing) — the comparison also short-circuits on the first differing
    // byte, so a patched runtime is reported faster than a clean one. And the
    // mapping is read-only and file-backed, so it costs address space, not RAM:
    // the pages are shared with every other libart mapping on the device.
    //
    // Mapping it once is also the safer order: the copy is captured at first scan,
    // before an attacker who arrives later could swap the file underneath us.
    static DiskExecSeg s_disk;
    static bool s_disk_ready = false;
    static bool s_disk_tried = false;
    if (!s_disk_tried) {
        s_disk_tried = true;
        s_disk_ready = open_disk_exec_seg(path, &s_disk);
    }
    if (!s_disk_ready) return false;

    // A size skew means the mapped libart is not the file we captured (a different
    // build, a bind-mounted APEX). Fail open rather than diff blindly.
    if (s_disk.filesz != live.p_filesz) return false;

    const uint64_t n = live.p_filesz;
    out->segment_bytes = n;

    // libart's .text is EXECUTE-ONLY on Android 10+ arm64, so it cannot be compared
    // in place — dereferencing it raises SIGSEGV/SEGV_ACCERR. Pull a readable copy
    // through /proc/self/mem first. Fail open (as the size-skew check above does) if
    // even that cannot read it: a detector that cannot see is not evidence of tamper.
    std::vector<uint8_t> live_copy(static_cast<size_t>(n));
    if (!platform::safe_read_code(reinterpret_cast<const void*>(live.addr()),
                                  live_copy.data(), live_copy.size())) {
        return false;
    }
    const uint8_t* live_text = live_copy.data();

    if (std::memcmp(live_text, s_disk.text, static_cast<size_t>(n)) == 0) {
        out->status = LibArtTextStatus::kOk;
        return true;
    }

    out->status = LibArtTextStatus::kPatched;
    // Locate the sites. Only reached once something is already known to be wrong,
    // so the linear walk costs nothing in the clean case.
    uint64_t run_start = 0, run_end = 0;
    bool in_run = false;
    for (uint64_t i = 0; i <= n; ++i) {
        const bool diff = (i < n) && (live_text[i] != s_disk.text[i]);
        if (diff) {
            ++out->diff_bytes;
            if (!in_run) { in_run = true; run_start = i; }
            run_end = i + 1;
        } else if (in_run && (i == n || i - run_end >= kSiteGap)) {
            in_run = false;
            ++out->sites_total;
            if (out->site_count < kLibArtMaxSites) {
                LibArtPatchSite& st = out->sites[out->site_count++];
                st.seg_offset = run_start;
                st.live_addr = static_cast<uint64_t>(live.addr()) + run_start;
                st.run_len = static_cast<uint32_t>(run_end - run_start);
                const uint64_t avail = n - run_start;
                const size_t take = static_cast<size_t>(
                    avail < kLibArtSiteBytes ? avail : kLibArtSiteBytes);
                std::memcpy(st.live, live_text + run_start, take);
                std::memcpy(st.disk, s_disk.text + run_start, take);
                if (take == kLibArtSiteBytes && decode_abs_jump(st.live, &st.target)) {
                    st.abs_jump_stub = true;
                    const uint64_t lo = static_cast<uint64_t>(live.addr());
                    st.target_outside_libart = (st.target < lo || st.target >= lo + n);
                }
            }
        }
    }
    return true;
}

std::vector<std::string> libart_verdict_records() {
    std::vector<std::string> out;
    LibArtTextScan scan{};
    if (!scan_libart_text(&scan)) {
        RLOGI("native_integrity: G10 libart text scan unavailable");
        return out;
    }
    if (scan.status != LibArtTextStatus::kPatched) {
        RLOGI("native_integrity: G10 libart text status=%s bytes=%llu",
              libart_text_status_name(scan.status),
              static_cast<unsigned long long>(scan.segment_bytes));
        return out;
    }
    RLOGI("native_integrity: G10 libart text PATCHED diff_bytes=%llu sites=%zu",
          static_cast<unsigned long long>(scan.diff_bytes), scan.sites_total);

    // ONE record, not one per site: the description is the bulk of a record, and
    // repeating it per patch site tripled the token for no extra information. The
    // sites travel as numbered fields, capped, with the true total alongside.
    bool proof_positive = false;
    for (size_t i = 0; i < scan.site_count; ++i) {
        if (scan.sites[i].abs_jump_stub && scan.sites[i].target_outside_libart) {
            proof_positive = true;
            break;
        }
    }

    std::string r = "libart_text_patched";
    r = append_field(r, proof_positive ? "CRITICAL" : "HIGH");
    r = append_field(r, "libart .text diverges from on-disk baseline");

    char buf[128];
    std::snprintf(buf, sizeof(buf), "sites=%zu", scan.sites_total);
    r = append_field(r, buf);
    std::snprintf(buf, sizeof(buf), "diff_bytes=%llu",
                  static_cast<unsigned long long>(scan.diff_bytes));
    r = append_field(r, buf);
    std::snprintf(buf, sizeof(buf), "segment_bytes=%llu",
                  static_cast<unsigned long long>(scan.segment_bytes));
    r = append_field(r, buf);

    for (size_t i = 0; i < scan.site_count; ++i) {
        const LibArtPatchSite& s = scan.sites[i];
        std::snprintf(buf, sizeof(buf), "site%zu=%#llx+%u", i,
                      static_cast<unsigned long long>(s.seg_offset), s.run_len);
        r = append_field(r, buf);
        r = append_field(r, "live" + std::to_string(i) + "=" + hex(s.live, kLibArtSiteBytes));
        r = append_field(r, "disk" + std::to_string(i) + "=" + hex(s.disk, kLibArtSiteBytes));
        if (s.abs_jump_stub) {
            std::snprintf(buf, sizeof(buf), "stub%zu=%#llx%s", i,
                          static_cast<unsigned long long>(s.target),
                          s.target_outside_libart ? ",outside" : ",inside");
            r = append_field(r, buf);
        }
    }
    if (scan.site_count == 0) {
        // Hash mismatch with no locatable sites (the file could not be re-read for
        // the diff). Still a real finding — say exactly that much and no more.
        r = append_field(r, "sites_unlocated=1");
    }
    out.push_back(std::move(r));
    return out;
}

}  // namespace dicore::native_integrity
