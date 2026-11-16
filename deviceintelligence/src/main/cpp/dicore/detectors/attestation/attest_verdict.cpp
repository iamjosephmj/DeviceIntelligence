#include "dicore/detectors/attestation/der/attest_der.h"      // pure DER parser (fuzzed in isolation, spec §4.4)
#include "dicore/detectors/attestation/policy/attest_roots.h"    // pinned Google attestation roots (DER)
#include "dicore/platform/framework_shim.h"  // TEE keygen up-call (native-driven attestation)
#include "dicore/core/verdict_cores.h"   // kAttestSoftwareOnly (shared with the orchestrator)

#include "dicore/crypto/certchain.h"

#include <jni.h>
#include <pthread.h>
#include <sys/random.h>
#include <cstring>
#include <vector>

// Spec 03 (S5) — native key-attestation verdict: cert-chain STRUCTURAL check
// (self-owned certchain/x509_lite: DN-chaining to a pinned Google root, NO
// signatures) + boot-state read from the leaf + challenge-echo freshness. The
// CRYPTOGRAPHIC chain verification is the backend's authority (ChainVerifier
// re-verifies every signature on the device-forwarded chain) — the "signed
// sensor" contract; see docs/specs/2026-08-22-mbedtls-retirement-design.md.
//
// The DER parsing lives in attest_der.cpp (pure, fuzzed); cert field extraction
// in dicore/crypto/x509_lite. This file owns the structural trust check, the
// native-owned nonce, and the JNI glue.
//
//   DICORE_ATTEST_ENFORCE == 2 (default, kill) : VALID chain + fresh + affirmatively-
//                                          bad boot (or fresh software-only) crashes
//                                          the process (watchdog). Unconditional —
//                                          no advisory mode; a non-kill build needs
//                                          an explicit macro override (no Gradle flag).

#ifndef DICORE_ATTEST_ENFORCE
#define DICORE_ATTEST_ENFORCE 2
#endif

#include "dicore/platform/obf.h"  // DI_OBF_ATTEST

namespace dicore {
namespace {

constexpr int kMaxChain = 12;  // sane upper bound on chain length

// Packed return codes (also the advisory dual-run signal):
//   -1                    : parse/verify ERROR -> UNKNOWN, fail-open, never kills
//   trust*100 + fresh*10 + bs  (trust 1 VALID / 2 UNTRUSTED; fresh 0/1;
//   bs 0 Verified,1 SelfSigned,2 Unverified,3 Failed,9 unknown)
//   e.g. 111 = VALID + fresh + SelfSigned, 211 = UNTRUSTED + fresh + SelfSigned;
//   BOTH kill — a bad boot state (bs 1/2/3) is lethal whether or not the chain
//   verifies to a pinned root (a genuine locked device reports bs 0, untouched).
//   +1000 added when the attestation is fresh AND affirmatively SOFTWARE-only
//   (attestationSecurityLevel == Software): no hardware-backed evidence at all.
//   Software attestation does NOT chain to the pinned hardware roots, so this
//   can't be trust-gated; freshness (our nonce echoed) proves it's THIS device's
//   real keystore, not a replayed/foreign chain. (Read the bootcode as code%1000.)
constexpr int kErr = -1;
int pack(bool trusted, bool fresh, int bs) {
    return (trusted ? 100 : 200) + (fresh ? 10 : 0) + (bs >= 0 && bs <= 3 ? bs : 9);
}

// Native-owned attestation nonce (challenge-echo freshness, spec 03 §3.2).
constexpr int kNonceLen = 32;
pthread_mutex_t g_nonce_mu = PTHREAD_MUTEX_INITIALIZER;
uint8_t g_nonce[kNonceLen];
bool g_nonce_set = false;

// Device-property honeypot cache: filled from the leaf on every attest_verdict_run.
pthread_mutex_t g_dev_mu = PTHREAD_MUTEX_INITIALIZER;
KdDeviceIds g_last_dev{};
int g_last_sl = -1;     // securityLevel of the last leaf (0 SW / 1 TEE / 2 StrongBox)
bool g_last_dev_valid = false;

bool challenge_is_fresh(const uint8_t* chal, size_t chal_len) {
    bool fresh = false;
    pthread_mutex_lock(&g_nonce_mu);
    if (g_nonce_set && chal != nullptr && chal_len == (size_t)kNonceLen) {
        fresh = (memcmp(chal, g_nonce, kNonceLen) == 0);
    }
    pthread_mutex_unlock(&g_nonce_mu);
    return fresh;
}

}  // namespace

// Native verdict core (shared by the Kotlin-driven JNI and the native
// orchestrator): parse + structurally chain to a pinned Google root (x509_lite),
// read the boot state from the verified leaf, check freshness, pack the code,
// and — when DICORE_ATTEST_ENFORCE==2 — crash on VALID+fresh+affirmatively-bad.
DI_OBF_ATTEST
int attest_verdict_run(const std::vector<std::vector<uint8_t>>& chain) {
    if (chain.empty() || chain.size() > (size_t)kMaxChain) return kErr;
    dicore::crypto::CertChain certs;
    dicore::crypto::CertChain trust;
    int result = kErr;
    bool leaf_ok = false;
    do {
        for (size_t i = 0; i < chain.size(); ++i) {
            const auto& d = chain[i];
            if (!d.empty() && d.size() <= kMaxCert) {
                int rc = certs.add_der(d.data(), d.size());
                if (i == 0) leaf_ok = (rc == 0);
            }
        }
        if (!leaf_ok) break;
        for (int i = 0; i < kGoogleAttestRootCount; ++i) {
            trust.add_der(kGoogleAttestRoots[i].der, kGoogleAttestRoots[i].len);
        }
        KdInfo kd;
        const uint8_t* ext_p = nullptr; size_t ext_len = 0;
        certs.leaf_extensions(&ext_p, &ext_len);
        kd_from_extensions(ext_p, ext_len, &kd);
        pthread_mutex_lock(&g_dev_mu);
        g_last_dev = kd.dev;
        g_last_sl = kd.sl;
        g_last_dev_valid = leaf_ok;
        pthread_mutex_unlock(&g_dev_mu);
        bool fresh = challenge_is_fresh(kd.chal, kd.chal_len);
        uint32_t flags = 0;
        int vrc = certs.verify(trust, &flags);
        bool trusted = (vrc == 0);
        bool software_only = fresh && kd.sl == 0;  // affirmative no-hardware evidence
        // Revocation: any cert in this device's live chain whose serial is on
        // Google's attestation revocation list = a known-leaked keybox = spoofer,
        // regardless of boot state (the spoofer fakes Verified). Fail-open.
        // [[maybe_unused]]: `revoked` is only read in the DICORE_ATTEST_ENFORCE==2
        // kill branch below, so a non-lethal override build (==0/1) must not trip
        // -Werror=unused-but-set-variable.
        [[maybe_unused]] bool revoked = false;
        for (const auto& s : certs.serials()) {
            if (crl_is_revoked(s.data(), s.size())) { revoked = true; break; }
        }
        result = pack(trusted, fresh, kd.bs) + (software_only ? kAttestSoftwareOnly : 0);
    } while (false);
    return result;  // CertChain releases on scope exit
}

// Fill this session's native-owned nonce (getrandom). false on failure.
bool attest_fill_nonce() {
    pthread_mutex_lock(&g_nonce_mu);
    bool ok = (getrandom(g_nonce, kNonceLen, 0) == (ssize_t)kNonceLen);
    g_nonce_set = ok;
    pthread_mutex_unlock(&g_nonce_mu);
    return ok;
}

// Native-driven attestation (orchestrator path): own the nonce -> up-call the
// TEE keygen (FrameworkShim) -> run the verdict. No Kotlin orchestration.
DI_OBF_ATTEST
int attest_run_native() {
    if (!attest_fill_nonce()) return kErr;
    uint8_t nonce[kNonceLen];
    pthread_mutex_lock(&g_nonce_mu);
    memcpy(nonce, g_nonce, kNonceLen);
    pthread_mutex_unlock(&g_nonce_mu);
    auto chain = fw_attest_chain(nonce, kNonceLen);
    if (chain.empty()) return kErr;
    return attest_verdict_run(chain);
}

namespace {
bool ascii_ieq(const char* a, const std::string& b) {
    if (b.size() != strlen(a)) return false;
    for (size_t i = 0; i < b.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}
// One attested field mismatches if BOTH sides are non-empty and they differ.
bool field_mismatch(const char* attested, const std::string& actual) {
    if (attested[0] == '\0' || actual.empty()) return false;  // can't compare -> not a tell
    return !ascii_ieq(attested, actual);
}
}  // namespace

DevicePropStatus attest_device_property_status() {
    pthread_mutex_lock(&g_dev_mu);
    KdDeviceIds d = g_last_dev;
    int sl = g_last_sl;
    bool valid = g_last_dev_valid;
    pthread_mutex_unlock(&g_dev_mu);
    if (!valid) return DevicePropStatus::kUnavailable;

    DeviceIdentity id = fw_device_identity();
    if (!id.ok) return DevicePropStatus::kUnavailable;       // fail-open

    if (d.any_present) {
        bool mismatch = field_mismatch(d.brand, id.brand) ||
                        field_mismatch(d.device, id.device) ||
                        field_mismatch(d.product, id.product) ||
                        field_mismatch(d.manufacturer, id.manufacturer) ||
                        field_mismatch(d.model, id.model);
        return mismatch ? DevicePropStatus::kMismatch : DevicePropStatus::kClean;
    }
    // Absent. Only a tell on a hardware-backed leaf (capability evidence); a
    // Software/unknown leaf that omits device-IDs is unsupported -> fail-open.
    return (sl == 1 || sl == 2) ? DevicePropStatus::kStripped
                                : DevicePropStatus::kUnavailable;
}

}  // namespace dicore
