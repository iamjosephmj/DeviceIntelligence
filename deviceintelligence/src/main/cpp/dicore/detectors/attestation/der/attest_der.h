#pragma once

#include <cstddef>
#include <cstdint>

// Pure, dependency-free DER parser for the Android key-attestation KeyDescription
// extension (spec 03). Split out of attest_verdict.cpp so it can be fuzzed in
// isolation (no JNI / crypto engine / watchdog), per spec 03 §4.4. This is the most
// dangerous code surface in the port (§4.0): it runs on attacker-influenced cert
// bytes and a bug can crash real users or be a code-exec vector. It is therefore
// fully bounds-checked and fail-open — a parse that does not complete cleanly
// yields UNKNOWN, never an affirmatively-bad value.

namespace dicore {

// Shared hard input cap (§4.3).
constexpr size_t kMaxCert = 1u << 16;  // 64 KB per cert

// Device identity attested in the leaf when the keygen sets
// setDevicePropertiesAttestationIncluded(true). Fixed-size COPIES (not pointers)
// so they outlive the parsed cert buffer. "" = that tag absent; any_present =
// at least one device-id tag was found.
struct KdDeviceIds {
    char brand[64] = {};
    char device[64] = {};
    char product[64] = {};
    char manufacturer[64] = {};
    char model[64] = {};
    bool any_present = false;
};

// One KeyDescription's facts the verdict needs.
struct KdInfo {
    int bs = -1;                    // verifiedBootState: 0 Verified,1 SelfSigned,
                                    // 2 Unverified,3 Failed, -1 UNKNOWN
    int sl = -1;                    // attestationSecurityLevel: 0 Software,
                                    // 1 TrustedEnvironment, 2 StrongBox, -1 UNKNOWN
    const uint8_t* chal = nullptr;  // attestationChallenge bytes (into caller's buffer)
    size_t chal_len = 0;
    KdDeviceIds dev;                // device-property attestation fields (v1 honeypot)
};

// Boot state from the X509Certificate.getExtensionValue() form (a DER OCTET
// STRING wrapping the KeyDescription SEQUENCE). Returns the boot-state code, or
// -1 on any truncation / unexpected tag / CBOR-EAT / missing field. THE fuzz
// entry point.
int attest_boot_state(const uint8_t* ext, size_t len);

// Parse a KeyDescription SEQUENCE (already unwrapped) into [out].
void parse_keydescription(const uint8_t* p, size_t len, KdInfo* out);

// Walk a leaf cert's raw extensions blob (the X.509 v3 extensions) for the
// KeyDescription extension and extract its facts into [out].
void kd_from_extensions(const uint8_t* exts, size_t len, KdInfo* out);

}  // namespace dicore
