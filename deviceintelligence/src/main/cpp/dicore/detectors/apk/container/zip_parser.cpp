#include "dicore/detectors/apk/container/zip_parser.h"

#include "dicore/platform/hex.h"
#include "dicore/platform/log.h"
#include "dicore/crypto/sha256.h"

#include "dicore/crypto/inflate.h"

#include <cstdlib>
#include <cstring>

namespace dicore::zip {

namespace {

constexpr uint32_t kEocdMagic = 0x06054b50;
constexpr uint32_t kCdfhMagic = 0x02014b50;
constexpr uint32_t kLfhMagic  = 0x04034b50;

constexpr size_t kEocdMinSize = 22;
constexpr size_t kCdfhMinSize = 46;
constexpr size_t kLfhMinSize  = 30;

// Max ZIP comment length (per spec).
constexpr size_t kMaxComment  = 0xFFFFu;

inline uint16_t rd16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24));
}

} // namespace

bool find_central_directory(const ApkMap& apk, CentralDirInfo* out) {
    if (!out) return false;
    *out = {};

    const uint8_t* base = apk.data();
    const size_t   sz   = apk.size();
    if (!base || sz < kEocdMinSize) return false;

    // Scan the last (kMaxComment + kEocdMinSize) bytes for the EOCD magic.
    size_t scan_window = sz < kMaxComment + kEocdMinSize
                                 ? sz
                                 : kMaxComment + kEocdMinSize;
    size_t start = sz - scan_window;

    // Walk backward from end-22.
    for (size_t off = sz - kEocdMinSize; ; --off) {
        if (rd32(base + off) == kEocdMagic) {
            const uint8_t* eocd = base + off;
            uint16_t comment_len = rd16(eocd + 20);
            // Sanity: the comment must fit in the remaining bytes.
            if ((size_t)comment_len + kEocdMinSize <= sz - off) {
                out->total_entries = rd16(eocd + 10);
                out->cd_size       = rd32(eocd + 12);
                out->cd_offset     = rd32(eocd + 16);

                if (out->cd_offset + out->cd_size > sz) {
                    RLOGE("zip: cd out of range (off=%llu sz=%llu apk=%zu)",
                          (unsigned long long)out->cd_offset,
                          (unsigned long long)out->cd_size,
                          sz);
                    return false;
                }
                // Treat 0xFFFF/0xFFFFFFFF sentinels as "ZIP64 needed";
                // we don't support ZIP64 in this flag.
                if (out->total_entries == 0xFFFFu
                    || out->cd_size == 0xFFFFFFFFu
                    || out->cd_offset == 0xFFFFFFFFu) {
                    RLOGW("zip: ZIP64 EOCD detected, not supported yet");
                    return false;
                }
                out->present = true;
                return true;
            }
        }
        if (off == start) break;
    }
    return false;
}

size_t hash_all_entries(const ApkMap& apk,
                        const CentralDirInfo& cdi,
                        const std::function<void(const EntryHash&)>& sink) {
    if (!cdi.present) return 0;

    const uint8_t* cd = apk.range((size_t)cdi.cd_offset, (size_t)cdi.cd_size);
    if (!cd) return 0;

    size_t hashed = 0;
    size_t cd_off = 0;

    for (uint64_t i = 0; i < cdi.total_entries; ++i) {
        if (cd_off + kCdfhMinSize > (size_t)cdi.cd_size) {
            RLOGE("zip: truncated cd at entry %llu", (unsigned long long)i);
            break;
        }
        const uint8_t* p = cd + cd_off;
        if (rd32(p) != kCdfhMagic) {
            RLOGE("zip: bad cdfh magic at cd_off=%zu", cd_off);
            break;
        }

        uint16_t method   = rd16(p + 10);
        uint32_t comp     = rd32(p + 20);
        uint16_t name_len = rd16(p + 28);
        uint16_t extra_len= rd16(p + 30);
        uint16_t cmt_len  = rd16(p + 32);
        uint32_t lfh_off  = rd32(p + 42);

        size_t fixed_end = cd_off + kCdfhMinSize;
        if (fixed_end + name_len + extra_len + cmt_len > (size_t)cdi.cd_size) {
            RLOGE("zip: cd entry overruns cd block at i=%llu",
                  (unsigned long long)i);
            break;
        }

        std::string name(reinterpret_cast<const char*>(p + kCdfhMinSize),
                         name_len);

        // Bridge to the LFH to learn the *real* body offset (LFH and CDFH
        // can have different extra-field lengths).
        const uint8_t* lfh = apk.range(lfh_off, kLfhMinSize);
        if (!lfh || rd32(lfh) != kLfhMagic) {
            RLOGW("zip: bad lfh at off=%u for entry '%s'",
                  lfh_off, name.c_str());
            cd_off += kCdfhMinSize + name_len + extra_len + cmt_len;
            continue;
        }
        uint16_t lfh_name_len  = rd16(lfh + 26);
        uint16_t lfh_extra_len = rd16(lfh + 28);

        uint64_t body_off = (uint64_t)lfh_off + kLfhMinSize
                            + lfh_name_len + lfh_extra_len;

        // ZIP64 sentinel guard.
        if (comp == 0xFFFFFFFFu) {
            RLOGW("zip: entry '%s' uses ZIP64 size, skipping",
                  name.c_str());
            cd_off += kCdfhMinSize + name_len + extra_len + cmt_len;
            continue;
        }

        const uint8_t* body = apk.range((size_t)body_off, (size_t)comp);
        if (!body) {
            RLOGW("zip: body out of range for '%s' (off=%llu sz=%u)",
                  name.c_str(), (unsigned long long)body_off, comp);
            cd_off += kCdfhMinSize + name_len + extra_len + cmt_len;
            continue;
        }

        uint8_t md[sha::kDigestLen];
        if (!sha::sha256(body, (size_t)comp, md)) {
            RLOGE("zip: sha256 failed for '%s'", name.c_str());
            cd_off += kCdfhMinSize + name_len + extra_len + cmt_len;
            continue;
        }

        EntryHash eh;
        eh.name        = std::move(name);
        eh.sha256_hex  = hex::encode(md, sha::kDigestLen);
        eh.body_offset = body_off;
        eh.body_size   = (uint64_t)comp;
        eh.method      = method;
        sink(eh);
        ++hashed;

        cd_off += kCdfhMinSize + name_len + extra_len + cmt_len;
    }

    return hashed;
}

bool hash_entry_decompressed(const ApkMap& apk,
                             const CentralDirInfo& cdi,
                             const std::string& name,
                             std::string* sha_hex_out) {
    if (!cdi.present || !sha_hex_out) return false;

    const uint8_t* cd = apk.range((size_t)cdi.cd_offset, (size_t)cdi.cd_size);
    if (!cd) return false;

    size_t cd_off = 0;
    for (uint64_t i = 0; i < cdi.total_entries; ++i) {
        if (cd_off + kCdfhMinSize > (size_t)cdi.cd_size) return false;
        const uint8_t* p = cd + cd_off;
        if (rd32(p) != kCdfhMagic) return false;

        uint16_t method    = rd16(p + 10);
        uint32_t comp      = rd32(p + 20);
        uint32_t uncomp    = rd32(p + 24);
        uint16_t name_len  = rd16(p + 28);
        uint16_t extra_len = rd16(p + 30);
        uint16_t cmt_len   = rd16(p + 32);
        uint32_t lfh_off   = rd32(p + 42);

        size_t fixed_end = cd_off + kCdfhMinSize;
        if (fixed_end + name_len + extra_len + cmt_len > (size_t)cdi.cd_size) return false;

        const size_t next_off = cd_off + kCdfhMinSize + name_len + extra_len + cmt_len;

        // Only the entry we're looking for needs the (more expensive) inflate;
        // skip past every other CDFH cheaply.
        if (name_len != name.size() ||
            std::memcmp(p + kCdfhMinSize, name.data(), name_len) != 0) {
            cd_off = next_off;
            continue;
        }

        // ZIP64-encoded sizes are unsupported here (fail-open).
        if (comp == 0xFFFFFFFFu || uncomp == 0xFFFFFFFFu) return false;

        // Bridge to the LFH for the real body offset (LFH/CDFH extra fields differ).
        const uint8_t* lfh = apk.range(lfh_off, kLfhMinSize);
        if (!lfh || rd32(lfh) != kLfhMagic) return false;
        uint16_t lfh_name_len  = rd16(lfh + 26);
        uint16_t lfh_extra_len = rd16(lfh + 28);
        uint64_t body_off = (uint64_t)lfh_off + kLfhMinSize + lfh_name_len + lfh_extra_len;

        const uint8_t* body = apk.range((size_t)body_off, (size_t)comp);
        if (!body) return false;

        uint8_t md[sha::kDigestLen];
        if (method == 0) {                       // Stored: body IS the plaintext.
            if (uncomp != 0 && uncomp != comp) return false;
            if (!sha::sha256(body, (size_t)comp, md)) return false;
        } else if (method == 8) {                // Deflate: raw inflate, then hash.
            size_t produced = 0;
            void* inflated = dicore::crypto::inflate_deflate(body, (size_t)comp, &produced);
            if (!inflated) return false;
            if (uncomp != 0 && produced != (size_t)uncomp) { free(inflated); return false; }
            bool ok = sha::sha256(reinterpret_cast<const uint8_t*>(inflated), produced, md);
            free(inflated);
            if (!ok) return false;
        } else {
            return false;                        // unknown method -> fail-open
        }

        *sha_hex_out = hex::encode(md, sha::kDigestLen);
        return true;
    }
    return false;  // entry not found
}

bool read_entry_raw(const ApkMap& apk,
                    const CentralDirInfo& cdi,
                    const std::string& name,
                    std::vector<uint8_t>* out) {
    if (!cdi.present || !out) return false;
    out->clear();

    // Decompressed-size ceiling: our assets are small (KB–low MB); this only
    // bounds a malicious over-large / zip-bomb entry so a hostile APK can't make
    // the core allocate unbounded memory.
    constexpr uint32_t kMaxEntryBytes = 64u * 1024 * 1024;  // 64 MiB

    const uint8_t* cd = apk.range((size_t)cdi.cd_offset, (size_t)cdi.cd_size);
    if (!cd) return false;

    size_t cd_off = 0;
    for (uint64_t i = 0; i < cdi.total_entries; ++i) {
        if (cd_off + kCdfhMinSize > (size_t)cdi.cd_size) return false;
        const uint8_t* p = cd + cd_off;
        if (rd32(p) != kCdfhMagic) return false;

        uint16_t method    = rd16(p + 10);
        uint32_t comp      = rd32(p + 20);
        uint32_t uncomp    = rd32(p + 24);
        uint16_t name_len  = rd16(p + 28);
        uint16_t extra_len = rd16(p + 30);
        uint16_t cmt_len   = rd16(p + 32);
        uint32_t lfh_off   = rd32(p + 42);

        size_t fixed_end = cd_off + kCdfhMinSize;
        if (fixed_end + name_len + extra_len + cmt_len > (size_t)cdi.cd_size) return false;
        const size_t next_off = cd_off + kCdfhMinSize + name_len + extra_len + cmt_len;

        // Cheap skip past every non-matching CDFH; only the target is decoded.
        if (name_len != name.size() ||
            std::memcmp(p + kCdfhMinSize, name.data(), name_len) != 0) {
            cd_off = next_off;
            continue;
        }

        if (comp == 0xFFFFFFFFu || uncomp == 0xFFFFFFFFu) return false;  // ZIP64
        if (uncomp > kMaxEntryBytes) return false;                      // bomb guard

        // Bridge to the LFH for the real body offset (LFH/CDFH extra fields differ).
        const uint8_t* lfh = apk.range(lfh_off, kLfhMinSize);
        if (!lfh || rd32(lfh) != kLfhMagic) return false;
        uint16_t lfh_name_len  = rd16(lfh + 26);
        uint16_t lfh_extra_len = rd16(lfh + 28);
        uint64_t body_off = (uint64_t)lfh_off + kLfhMinSize + lfh_name_len + lfh_extra_len;

        const uint8_t* body = apk.range((size_t)body_off, (size_t)comp);
        if (!body) return false;

        if (method == 0) {                        // Stored: body IS the plaintext.
            if (uncomp != 0 && uncomp != comp) return false;
            out->assign(body, body + comp);
            return true;
        } else if (method == 8) {                 // Deflate: raw inflate.
            size_t produced = 0;
            void* inflated = dicore::crypto::inflate_deflate(body, (size_t)comp, &produced);
            if (!inflated) return false;
            if (produced > kMaxEntryBytes || (uncomp != 0 && produced != (size_t)uncomp)) {
                free(inflated);
                return false;
            }
            const uint8_t* q = reinterpret_cast<const uint8_t*>(inflated);
            out->assign(q, q + produced);
            free(inflated);
            return true;
        }
        return false;                             // unknown method -> fail-open
    }
    return false;  // entry not found
}

} // namespace dicore::zip
