#pragma once

// Native keystore2 client (Phase 2 of the JVM-shim migration).
//
// Replaces the FrameworkShim keystore up-calls (q ops 7/8/14/15) with a native
// binder client to `android.system.keystore2.IKeystoreService`, so attested
// key generation and signing carry NO ART-hookable JVM surface. The attested
// key still lives in the TEE/StrongBox; moving the *call* into native only
// removes the `FrameworkShim.a7/a9/a16/a17` methods as LSPosed hook points.
//
// STATUS: SCAFFOLD. The service acquisition, tag constants, and parcel helpers
// are real; the exact stable-AIDL parcelable field order and transaction codes
// are marked `KS2_VERIFY` and MUST be validated on-device (against this device's
// keystore2 AIDL version) before this path is wired into the orchestrator. Until
// then every entry point fails open (returns empty) so linking it changes no
// behavior. Requires API 31+ (keystore2); callers gate on that.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dicore::ks2 {

// The five Build.* device-identity values to attest as ATTESTATION_ID_* tags,
// so the backend device-property honeypot has hardware-signed identity to compare.
// All empty => request no device-ID attestation (older devices / opt-out).
struct DeviceProps {
    std::string brand, device, product, manufacturer, model;
    bool any() const {
        return !brand.empty() || !device.empty() || !product.empty() ||
               !manufacturer.empty() || !model.empty();
    }
};

// Security level to force for the generated key.
enum class Level { kTee, kStrongBox };

// True if `android.system.keystore2.IKeystoreService/default` is reachable.
// Cheap feature probe; false on pre-31 or a device without keystore2.
bool available();

// Generate an attested EC P-256 signing key at [alias] with [nonce] as the
// attestation challenge and (when [props].any()) the device-ID tags attested,
// at security [level]. Returns the certificate chain (leaf first) as DER blobs,
// mirroring fw_session_keygen/fw_attest_chain. Empty on any failure (fail-open).
std::vector<std::vector<uint8_t>> generate_attested_key(
    const std::string& alias, const uint8_t* nonce, size_t nonce_len,
    const DeviceProps& props, Level level);

// ECDSA-SHA256-sign [msg] with the existing key at [alias]. Returns the DER
// signature, empty on failure. Mirrors fw_session_sign.
std::vector<uint8_t> sign(const std::string& alias, const uint8_t* msg, size_t msg_len);

}  // namespace dicore::ks2
