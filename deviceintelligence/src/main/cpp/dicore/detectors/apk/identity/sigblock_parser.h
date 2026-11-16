#pragma once

#include "dicore/detectors/apk/container/apkmap.h"
#include "dicore/detectors/apk/container/zip_parser.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dicore::sigblock {

struct SignerCerts {
    // Hex SHA-256 of each signer certificate (DER-encoded), in the order
    // they appear in the signing block. Empty if no v2/v3 block was found
    // or parsing failed.
    std::vector<std::string> cert_sha256_hex;

    // Source of the certs, for debugging.
    enum class Source : uint8_t { kNone, kV2, kV3 } source = Source::kNone;
};

// Locate the APK Signing Block (v2/v3) just before the central directory
// and extract per-signer certificate SHA-256 hashes. Returns false if no
// signing block is present or if the block is malformed.
//
// We prefer v3 if both v2 and v3 are present (v3 is always a superset of
// v2 for verification purposes); otherwise we fall back to v2.
bool extract_signer_certs(const ApkMap& apk,
                          const zip::CentralDirInfo& cdi,
                          SignerCerts* out);

} // namespace dicore::sigblock
