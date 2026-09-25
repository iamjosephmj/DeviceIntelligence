#pragma once

#include <jni.h>
#include <cstdint>
#include <string>
#include <vector>

// Native side of the JVM up-call surface (spec 03 §1/§3). As native becomes the
// orchestrator, it fetches the handful of framework-only values from the
// logic-free Kotlin `FrameworkShim` via JNI. The JavaVM is cached at JNI_OnLoad;
// up-calls AttachCurrentThread as needed. Any failure (no VM, class/method not
// found, exception) returns an empty/false/-1 "unknown" — never throws.

namespace dicore {

// Called once from JNI_OnLoad to cache the JavaVM for later up-calls.
void framework_shim_set_vm(JavaVM* vm);

// The cached JavaVM (or null before JNI_OnLoad). Used by the continuous re-sweep
// thread to attach its own JNIEnv for the env-using cores (ART hook scan).
JavaVM* framework_shim_get_vm();

// One up-call per framework value (no-arg static methods on FrameworkShim).
std::string fw_package_name();
std::string fw_source_dir();
std::string fw_installer_package();
// "1" if the device declares FEATURE_STRONGBOX_KEYSTORE, "0" if not, "" if unknown.
// Reported into the enroll bundle so the backend can tell a genuinely StrongBox-less
// device from one whose StrongBox keygen failed transiently.
std::string fw_strongbox_feature();

// SHA-256 (lowercase hex) of this APK's first signing certificate; "" if unknown.
// A SELF-REPORT: app-visible and patchable, so it carries no weight on its own. It
// is on the wire only to be cross-checked backend-side against the TEE-signed
// attestationApplicationId — the DISAGREEMENT is the finding.
std::string fw_signing_digest();

// The fingerprint inputs that need the JVM, '\n'-joined in a fixed order:
//   widevineId, widevineLevel, androidId
// Any unavailable field is empty; the field count is always three. Kernel, build
// fingerprint and security patch are read natively instead — they feed INTEL_0019
// and must not cross an ART-hookable surface. The two identity fields are hashed
// before they reach the wire; see fp_pepper.h.
std::string fw_fingerprint_raw();

std::string fw_primary_abi();

// The encrypted fingerprint baseline bytes from the on-disk APK (ZipFile read
// in the shim); empty on failure. Native owns the decode/diff (apk_verdict).
std::vector<uint8_t> fw_fingerprint_asset();

// Up-call the TEE keygen with [nonce] as the attestation challenge; returns the
// raw cert-chain DER (leaf first), or empty on failure. The one heavy
// framework dependency (no NDK keygen API).
std::vector<std::vector<uint8_t>> fw_attest_chain(const uint8_t* nonce, size_t nonce_len);

// Cross-level attestation (op 8): returns {strongBoxChain, teeChain}; each chain
// is leaf-first DER. Either inner chain may be empty (level unavailable / failure).
std::vector<std::vector<std::vector<uint8_t>>>
fw_attest_chains_xlevel(const uint8_t* nonce, size_t nonce_len);

// The encrypted attestation-revocation-list asset (q op 9), read from the on-disk
// APK via ZipFile; empty on failure. Native owns the decrypt/parse (attest_crl).
std::vector<uint8_t> fw_crl_asset();

// The pinned server public key asset (server.key) for v2 ECIES tokens.
// Native-only (NO JVM up-call, by design) — empty on any failure.
std::vector<uint8_t> fw_licence_asset();

// Dex provenance (q op 13): every dex element in a REACHABLE class loader (app
// loader chain + thread context loaders), as "<loaderClass>\x1f<dexPathOrEmpty>".
// Native builds the legit set (fw_source_dir + split_source_dirs) and flags
// in-memory dex (empty path) or a dex loaded from an attacker-writable path.
// Empty on failure (fail-open). Owns no policy.
std::vector<std::string> fw_dex_entries();

// App Bundle split APK paths (q op 10): applicationInfo.splitSourceDirs, one path
// per element. Empty when the install has no splits (plain APK) or on failure.
// Used by bundle-mode integrity to hash baked entries across base + every split.
std::vector<std::string> split_source_dirs();

// This device's identity (Build.*), acquired via op 11 for the device-property
// attestation honeypot. ok==false on any failure (native then fails open).
struct DeviceIdentity {
    std::string brand;
    std::string device;
    std::string product;
    std::string manufacturer;
    std::string model;
    bool ok = false;
};
DeviceIdentity fw_device_identity();

// Attest-once session key: op 14 generates it (returns [spki, leaf, chain...]),
// op 15 signs a message with it. See docs/specs/2026-08-20-attest-once-challenge-design.md.
std::vector<std::vector<uint8_t>> fw_session_keygen(const uint8_t* nonce, size_t nonce_len);
bool fw_session_sign(const uint8_t* msg, size_t msg_len, std::vector<uint8_t>& out);

// The SOFTWARE rung of the signing ladder, used only when the attested session key
// is unavailable. Proves nothing about the device; provides continuity only.
std::vector<uint8_t> fw_fallback_key_spki();
bool fw_fallback_sign(const uint8_t* msg, size_t msg_len, std::vector<uint8_t>& out);

// Sub-code for the last attested-keygen failure, e.g. "strongbox_unavailable:-68".
std::string fw_last_keygen_error();

}  // namespace dicore
