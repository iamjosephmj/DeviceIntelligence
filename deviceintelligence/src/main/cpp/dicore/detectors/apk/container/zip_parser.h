#pragma once

#include "dicore/detectors/apk/container/apkmap.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

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

// Hash the DECOMPRESSED body of a single named entry: Stored (method 0) is a
// passthrough; Deflate (method 8) is inflated via dicore::crypto::inflate before
// hashing. Used by App Bundle ("bundle mode") integrity, where Play re-encodes
// the split APKs so only the inflated bytes are stable across build and device.
//
// Returns true and fills [sha_hex_out] with 64 lowercase hex chars on success;
// returns false (fail-open, never a crash) on a missing entry, ZIP64-encoded
// sizes, an unknown compression method, an inflate error, or a size mismatch.
bool hash_entry_decompressed(const ApkMap& apk,
                             const CentralDirInfo& cdi,
                             const std::string& name,
                             std::string* sha_hex_out);

// Read the DECOMPRESSED bytes of a single named entry into [out] — the native
// equivalent of ZipFile.getInputStream(entry).readBytes(): Stored (method 0) is a
// passthrough, Deflate (method 8) is inflated. Lets the native core read its own
// APK assets (fingerprint.bin, crl.bin) directly, replacing the FrameworkShim
// ZipFile up-calls (q ops 6/9). Returns true and fills [out] on success; fail-open
// (false, [out] cleared, never a crash) on a missing entry, ZIP64-encoded sizes, an
// unknown method, an inflate error, a size mismatch, or an entry whose decompressed
// size exceeds the internal bomb cap.
bool read_entry_raw(const ApkMap& apk,
                    const CentralDirInfo& cdi,
                    const std::string& name,
                    std::vector<uint8_t>* out);

} // namespace dicore::zip
