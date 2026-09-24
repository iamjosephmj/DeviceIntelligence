#include "dicore/detectors/attestation/der/attest_der.h"      // kMaxCert
#include "dicore/platform/framework_shim.h"
#include "dicore/core/verdict_cores.h"
#include "dicore/platform/obf.h"             // DI_OBF_ATTEST

#include "dicore/crypto/certchain.h"

#include <sys/random.h>
#include <cstring>
#include <vector>

// Layer 2 (RKP root convergence) is OFF by default. Its false-positive surface on
// non-Pixel / non-RKP API>=33 devices is unvalidated: a genuine device that does
// NOT split its StrongBox/TEE roots is indistinguishable from a spoofer, and that
// cannot be tuned away (a genuine non-RKP chain and a forged one look identical).
// Build with -DDICORE_XLEVEL_RKP=1 to enable it once validated across a device
// fleet. Layer 1 (batch-key reuse) is always on — it cannot false-positive on
// genuine hardware (two secure elements never share an attestation key).
#ifndef DICORE_XLEVEL_RKP
#define DICORE_XLEVEL_RKP 0
#endif

#if DICORE_XLEVEL_RKP
#include <android/api-level.h>
#endif

// Cross-security-level attestation-spoofer check (spec 03). Self-referential — it
// makes the device contradict ITSELF, so it needs no genuine baseline nor pinned
// roots:
//
//   Layer 1 (batch-key reuse, ALWAYS ON): a genuine device provisions the
//     StrongBox and TEE attestation keys SEPARATELY, so the cert that signs each
//     leaf (chain[1]) differs. A single replayed leaked keybox (TrickyStore/
//     TEESimulator) signs both with the SAME key — impossible on genuine hardware.
//   Layer 2 (RKP root assertion, OPT-IN via DICORE_XLEVEL_RKP): on an RKP-era
//     device the TEE attestation roots online to a DISTINCT RKP CA while StrongBox
//     roots to the legacy static root, so the chain ROOTS differ. A replayed static
//     keybox roots both to the same CA. See the flag note above re: FP surface.
//
// Returns a bitmask: bit0(1)=batch-key reuse, bit1(2)=root convergence (only
// possible when DICORE_XLEVEL_RKP). 0 = clean, incl. fail-open (a level
// unavailable / a chain unparsable). No StrongBox -> empty StrongBox chain ->
// both layers fail open (the StrongBox slot never falls back to TEE, which would
// false-positive).

namespace dicore {
namespace {

constexpr int kXNonceLen = 32;
#if DICORE_XLEVEL_RKP
constexpr int kRkpEraApi = 33;   // Android 13 — RKP became the norm for new devices.
#endif

// SubjectPublicKeyInfo bytes of chain[idx]. false if idx is out of range, the cert
// is oversized, or it does not parse.
DI_OBF_ATTEST __attribute__((noinline))
bool cert_spki(const std::vector<std::vector<uint8_t>>& chain, size_t idx,
               std::vector<uint8_t>* out) {
    if (idx >= chain.size() || chain[idx].empty() || chain[idx].size() > kMaxCert) return false;
    std::vector<uint8_t> spki =
        dicore::crypto::spki_of_der(chain[idx].data(), chain[idx].size());
    if (spki.empty()) return false;
    *out = std::move(spki);
    return true;
}

bool spki_eq(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    return !a.empty() && a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace

DI_OBF_ATTEST
int attest_xlevel_run() {
    uint8_t nonce[kXNonceLen];
    if (getrandom(nonce, kXNonceLen, 0) != (ssize_t)kXNonceLen) return 0;
    auto chains = fw_attest_chains_xlevel(nonce, kXNonceLen);
    if (chains.size() < 2) return 0;
    const auto& sb = chains[0];
    const auto& tee = chains[1];

    int result = 0;

    // Layer 1 — batch (attestation-key) identity. chain[1] signs the leaf.
    std::vector<uint8_t> sb_batch, tee_batch;
    if (cert_spki(sb, 1, &sb_batch) && cert_spki(tee, 1, &tee_batch) &&
        spki_eq(sb_batch, tee_batch)) {
        result |= 1;
    }

#if DICORE_XLEVEL_RKP
    // Layer 2 — RKP root assertion (opt-in): StrongBox and TEE must root to
    // DIFFERENT CAs on an RKP-era device. Same root => one replayed static keybox.
    if (android_get_device_api_level() >= kRkpEraApi) {
        std::vector<uint8_t> sb_root, tee_root;
        if (cert_spki(sb, sb.size() - 1, &sb_root) &&
            cert_spki(tee, tee.size() - 1, &tee_root) &&
            spki_eq(sb_root, tee_root)) {
            result |= 2;
        }
    }
#endif

    return result;
}

}  // namespace dicore
