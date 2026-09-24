#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore::crypto {

// Parsed server public key from a licence asset.
//
//   RVN1 (72 bytes, legacy, unsigned):
//     magic(4)="RVN1" ver(1)=1 epoch(1) curve(1)=1(X25519) rsvd(1)
//     pubkey(32) checksum(32)
//
//   RVN2 (144 bytes, signed and package-bound):
//     magic(4)="RVN2" ver(1)=2 epoch(1) curve(1)=1(X25519) flags(1)
//     pubkey(32) pkg_hash(32) not_after(8, big-endian) sig(64)
//
// RVN1 parses with pkg_hash zeroed and not_after 0, so the caller can tell an
// unbound blob from one bound to the empty string.
struct LicenceKey {
    uint8_t pubkey[32];
    uint8_t pkg_hash[32];   // SHA-256(applicationId); all-zero for RVN1
    uint64_t not_after;     // epoch seconds; 0 = no expiry
    uint8_t epoch;
};

// Parse+validate a licence blob. RVN1 is checked by length, magic, version, curve
// and checksum; RVN2 by length, magic, version, curve, a constant-time signature
// compare over bytes[0..79], and a zero reserved tail. Returns false on any
// mismatch.
//
// The RVN2 signature is HMAC-SHA256 with a key baked into this binary. That is a
// FAIL-FAST against lifting the .so plus assets into another APK, NOT a security
// control: an attacker who can extract the key can equally well patch out this
// call. The enforcing licence check is backend-side, on the attested app identity.
bool licence_blob_parse(const uint8_t* buf, size_t len, LicenceKey* out);

// Test-only: write the 64-byte signature for body[0..79] into out[0..63]. Declared
// so host tests can build a valid blob; not part of the device contract.
void licence_blob_sign_for_test(const uint8_t* body80, uint8_t* out64);

} // namespace dicore::crypto
