#pragma once

#include "apkmap.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace dicore::zip {

struct CentralDirInfo {
    uint64_t cd_offset       = 0;
    uint64_t cd_size         = 0;
    uint64_t total_entries   = 0;
    bool     present         = false;
};

// Locate End-of-Central-Directory record and read the central directory
// metadata. Does not allocate. Returns false if the EOCD signature isn't
// found or the central directory is out of range.
bool find_central_directory(const ApkMap& apk, CentralDirInfo* out);

// Result of hashing a single ZIP entry.
struct EntryHash {
    std::string name;          // entry path within the APK
    std::string sha256_hex;    // 64 lowercase hex chars
    uint64_t    body_offset;   // file offset to compressed body
    uint64_t    body_size;     // compressed size from CDFH
    uint16_t    method;        // 0 = stored, 8 = deflate, etc.
};

// Walk every entry in the central directory and invoke `sink` for each
// computed entry hash. The sink is called in CD order. Hashing is over
// the COMPRESSED (= on-disk) bytes of the file, which is deterministic
// for a given build (the plugin sees the same bytes the device sees) and
// catches all content-level tampering as well as recompression.
//
// Returns the number of successfully hashed entries (skips entries we
// can't safely interpret, such as ZIP64-encoded body sizes for now).
size_t hash_all_entries(const ApkMap& apk,
                        const CentralDirInfo& cdi,
                        const std::function<void(const EntryHash&)>& sink);

// Hash the DECOMPRESSED body of the ZIP entry named `entry_name`.
// For STORED entries, SHA-256 the raw body directly.
// For DEFLATED entries, inflate via NDK zlib (raw deflate, inflateInit2(-MAX_WBITS))
// into a bounded buffer and SHA-256 the inflated bytes.
// Writes 32 bytes to out32 on success and returns true.
// Returns false (fail-closed, no crash) if: entry not found, null entry_name,
// ZIP64 sentinel, zlib error, inflated size > 64 MB guard, or body out of range.
bool hash_entry_decompressed(const ApkMap& apk,
                             const CentralDirInfo& cdi,
                             const char* entry_name,
                             uint8_t out32[32]);

} // namespace dicore::zip
