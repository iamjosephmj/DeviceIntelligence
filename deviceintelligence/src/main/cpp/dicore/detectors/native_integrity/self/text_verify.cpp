#include "dicore/detectors/native_integrity/self/text_verify.h"

#include "dicore/platform/log.h"
#include "dicore/platform/safe_text_read.h"

#include <vector>
#include "dicore/crypto/sha256.h"
#include "dicore/platform/protected_store.h"
#include "dicore/detectors/native_integrity/process/range_map.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>

namespace dicore::native_integrity {

namespace {

// Self-protected baseline storage. Same shape as
// art_integrity/snapshot.cpp's design: two independently mmap'd
// pages kept at PROT_NONE between scans, with the second page
// holding a SHA-256 of the first. PROT_READ briefly for each
// scan, recompute the hash-of-the-baseline, compare, then
// PROT_NONE again.
//
// The baseline being protected here is the runtime snapshot of
// the .text hash itself (32 bytes). It's tiny so the "values"
// page is mostly padding — the hash-of-hash check is what makes
// an attacker who flipped PROT_NONE→RW notice the moment they
// touched the digest.
ProtectedStore g_store;
std::atomic<bool> g_baseline_set{false};
std::mutex g_mutex;

// Build-time expected hash, populated lazily by
// `set_expected_text_hash`. 32 bytes when present; the
// `g_expected_known` flag distinguishes "v1 fingerprint, no
// expected hash to compare against" from "expected hash is all
// zeros" (which is itself a build error worth reporting on).
uint8_t g_expected[32] = {};
bool g_expected_known = false;
std::mutex g_expected_mutex;

bool compute_text_sha(uint8_t out[32]) {
    const auto layout = libdicore_layout();
    if (layout.rx_start == 0 || layout.rx_end <= layout.rx_start) return false;
    const size_t len = layout.rx_end - layout.rx_start;
    // Staged through /proc/self/mem rather than hashed in place. Our own .so is not
    // built execute-only today, but the Android 10 XOM crash showed that assuming
    // code memory is readable is exactly the assumption that breaks per-OEM.
    std::vector<uint8_t> copy(len);
    if (!platform::safe_read_code(reinterpret_cast<const void*>(layout.rx_start),
                                  copy.data(), copy.size())) {
        return false;
    }
    return sha::sha256(copy.data(), copy.size(), out);
}

bool hex_to_bytes32(const char* hex, uint8_t out[32]) {
    if (hex == nullptr) return false;
    size_t i = 0;
    for (i = 0; i < 64; ++i) {
        const char c = hex[i];
        if (c == '\0') return false;
        uint8_t nib;
        if (c >= '0' && c <= '9')      nib = c - '0';
        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
        else return false;
        if ((i & 1) == 0) out[i / 2] = static_cast<uint8_t>(nib << 4);
        else out[i / 2] |= nib;
    }
    return hex[i] == '\0';
}

}  // namespace

const char* text_status_name(TextStatus s) {
    switch (s) {
        case TextStatus::UNAVAILABLE:    return "unavailable";
        case TextStatus::OK:             return "ok";
        case TextStatus::HASH_MISMATCH:  return "hash_mismatch";
        case TextStatus::DRIFTED:        return "drifted";
    }
    return "unavailable";
}

void initialize_text_verify() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_baseline_set.load(std::memory_order_acquire)) return;
    uint8_t snap[32] = {};
    if (!compute_text_sha(snap)) {
        RLOGW("native_integrity: G2 init: failed to hash .text (sha backend or range)");
        return;
    }
    // Store the .text hash under the self-protecting store: seal() SHA-256s the
    // snapshot page so a tamper-after-PROT_NONE-flip is caught on the next scan.
    if (!g_store.init(sizeof(snap))) return;
    std::memcpy(g_store.values(), snap, sizeof(snap));
    g_store.seal();
    g_baseline_set.store(true, std::memory_order_release);

    const auto layout = libdicore_layout();
    char hex[65] = {};
    static const char kH[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        hex[i * 2] = kH[(snap[i] >> 4) & 0xF];
        hex[i * 2 + 1] = kH[snap[i] & 0xF];
    }
    RLOGI(
        "native_integrity: G2 text snapshot captured size=%zuB sha256=%s",
        layout.rx_end - layout.rx_start,
        hex
    );
}

void set_expected_text_hash(const char* hex32) {
    std::lock_guard<std::mutex> lock(g_expected_mutex);
    if (hex32 == nullptr || hex32[0] == '\0') {
        g_expected_known = false;
        std::memset(g_expected, 0, sizeof(g_expected));
        RLOGI("native_integrity: G2 expected hash cleared (v1 fingerprint or absent)");
        return;
    }
    uint8_t bytes[32] = {};
    if (!hex_to_bytes32(hex32, bytes)) {
        g_expected_known = false;
        std::memset(g_expected, 0, sizeof(g_expected));
        RLOGW("native_integrity: G2 expected hash malformed (length != 64 hex)");
        return;
    }
    std::memcpy(g_expected, bytes, sizeof(bytes));
    g_expected_known = true;
    RLOGI("native_integrity: G2 expected text hash installed");
}

bool scan_text(TextScan* out) {
    if (out == nullptr) return false;
    std::memset(out, 0, sizeof(*out));
    out->status_vs_expected = TextStatus::UNAVAILABLE;
    out->status_vs_snapshot = TextStatus::UNAVAILABLE;

    if (!g_baseline_set.load(std::memory_order_acquire)) return false;

    const auto layout = libdicore_layout();
    if (layout.rx_start == 0 || layout.rx_end <= layout.rx_start) return false;
    out->segment_bytes = layout.rx_end - layout.rx_start;

    if (!compute_text_sha(out->live)) return false;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_store.unprotect()) {
        // Toggle failed; report unavailable rather than false-positive.
        return false;
    }
    std::memcpy(out->snapshot, g_store.values(), sizeof(out->snapshot));
    // Hash-of-hash audit: an attacker who PROT_NONE->RW'd the values page and
    // rewrote the snapshot fails intact().
    bool baseline_intact = g_store.intact();
    g_store.reprotect();

    if (!baseline_intact) {
        // Baseline page itself was tampered with — report DRIFTED
        // (which is the right semantic: we can no longer trust the
        // snapshot, treat as if .text drifted).
        out->status_vs_snapshot = TextStatus::DRIFTED;
        RLOGW("native_integrity: G2 baseline hash-of-hash mismatch");
    } else if (std::memcmp(out->live, out->snapshot, sizeof(out->live)) == 0) {
        out->status_vs_snapshot = TextStatus::OK;
    } else {
        out->status_vs_snapshot = TextStatus::DRIFTED;
    }

    {
        std::lock_guard<std::mutex> elock(g_expected_mutex);
        out->expected_known = g_expected_known;
        if (g_expected_known) {
            std::memcpy(out->expected, g_expected, sizeof(out->expected));
            out->status_vs_expected =
                std::memcmp(out->live, out->expected, sizeof(out->live)) == 0
                    ? TextStatus::OK
                    : TextStatus::HASH_MISMATCH;
        } else {
            out->status_vs_expected = TextStatus::UNAVAILABLE;
        }
    }
    return true;
}

}  // namespace dicore::native_integrity
