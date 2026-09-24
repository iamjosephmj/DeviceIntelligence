#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// Spec 04 — native, byte-faithful decode of the build-time fingerprint blob
// (assets/tech.thessemaj.deviceintelligence/fingerprint.bin). The blob is XOR-encrypted
// with a 32-byte key and framed with Java DataInputStream semantics (big-endian
// ints, 2-byte-length-prefixed UTF-8). This is a §4.3 attack-surface parser (runs
// on a baked-but-attacker-replaceable asset), so every read is bounds-checked and
// any malformation degrades to a typed failure — never a crash, never a defaulted
// "clean" field. Mirrors FingerprintCodec.kt exactly (verified by the parity
// harness + fuzzer); the gradle encoder is the source of truth for the layout.

namespace dicore::fp {

// Mirrors the Kotlin DecodeResult failure taxonomy (the asset-read + key-assembly
// failures stay Kotlin-side; these are the blob-parse outcomes).
enum class Status : int {
    kOk = 0,
    kBadMagic = 1,         // first 4 bytes != magic (wrong key or replaced blob)
    kFormatMismatch = 2,   // formatVersion outside [1, 3] (version skew)
    kCorrupt = 3,          // truncation / bad UTF / negative-or-oversized count
};

struct Fingerprint {
    int schema_version = 0;
    std::string plugin_version;
    std::string variant_name;
    std::string application_id;
    std::vector<std::string> signer_cert_sha256;
    std::vector<std::pair<std::string, std::string>> entries;  // name -> sha256 hex
    std::vector<std::string> ignored_entries;
    std::vector<std::string> ignored_entry_prefixes;
    std::string expected_source_dir_prefix;
    std::vector<std::string> expected_installer_whitelist;
    // v2 (empty for v1 blobs):
    // native_lib_inventory_by_abi is parsed and carried in the __meta row but has no
    // runtime consumer since the lib_inventory scanner was removed (#17); kept for
    // meta/wire stability. dicore_text_sha256_by_abi IS consumed (the G2 text hash).
    std::vector<std::pair<std::string, std::vector<std::string>>> native_lib_inventory_by_abi;
    std::vector<std::pair<std::string, std::string>> dicore_text_sha256_by_abi;
    // v3 (false / empty for v1-v2 blobs):
    bool bundle_mode = false;
    std::vector<std::pair<std::string, std::string>> bundle_entry_hashes;  // name -> decompressed sha256 hex
};

// XOR-decrypt [cipher,clen) with the cycling [key,klen), then parse. Returns the
// status; fills [out] only on kOk. Never aborts/over-reads on any input.
Status decode(const uint8_t* cipher, size_t clen,
              const uint8_t* key, size_t klen, Fingerprint* out);

// Deterministic canonical digest of a decoded fingerprint, used to diff the
// native decode against the Kotlin reference in the parity harness. Both sides
// must produce byte-identical strings for the same blob.
std::string canonical_digest(const Fingerprint& fp);

}  // namespace dicore::fp
