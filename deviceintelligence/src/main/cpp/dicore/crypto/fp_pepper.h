#pragma once

#include "dicore/crypto/licence_blob.h"

#include <cstdint>
#include <string>

namespace dicore::crypto {

// The fingerprint pepper, DERIVED rather than stored:
//   pepper = SHA-256("intel-fp-pepper-v1" || LicenceKey.pubkey)
//
// Deriving it from the server public key already in the licence blob avoids
// widening RVN2 (which shipped at 144 bytes and is parsed, generated and baked
// into committed dev blobs). The pubkey is already epoch-versioned and stable
// across app releases, which is exactly the lifecycle a pepper needs.
//
// The pepper is what makes hashing worth doing: a bare SHA-256 of a device-wide
// identifier is STILL a device-wide identifier, just in hex. Peppering scopes it
// to this deployment, so the stored value is useless to anyone else.
//
// CONSEQUENCE, and it is not small: rotating the licence epoch re-peppers every
// device, so every user appears new to fraud matching. Key rotation is now a
// re-identification event, not a routine refresh.
void fp_pepper(const LicenceKey& key, uint8_t out[32]);

// hex(SHA-256(pepper || value)). Returns false for an empty value WITHOUT
// touching *out_hex: an identifier that could not be read must stay absent, not
// collapse to the hash of "" that every such device would share.
bool fp_hash(const uint8_t* pepper, const std::string& value, std::string* out_hex);

} // namespace dicore::crypto
