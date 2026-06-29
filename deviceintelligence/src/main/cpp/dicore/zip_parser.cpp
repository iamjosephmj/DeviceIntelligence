#include "zip_parser.h"

#include "hex.h"
#include "log.h"
#include "sha256.h"

#include <cstring>
#include <zlib.h>

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

// Maximum decompressed entry size accepted by hash_entry_decompressed.
// Entries larger than this are skipped (fail-closed). 64 MB covers the
// largest realistic dex/so in production; a real tamper attempt has no
// incentive to inflate to this size.
constexpr size_t kMaxInflateBytes = 64u * 1024u * 1024u;

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
                             const char* entry_name,
                             uint8_t out32[32]) {
    if (!cdi.present || !entry_name) return false;

    const uint8_t* cd = apk.range((size_t)cdi.cd_offset, (size_t)cdi.cd_size);
    if (!cd) return false;

    size_t cd_off = 0;
    for (uint64_t i = 0; i < cdi.total_entries; ++i) {
        if (cd_off + kCdfhMinSize > (size_t)cdi.cd_size) break;
        const uint8_t* p = cd + cd_off;
        if (rd32(p) != kCdfhMagic) break;

        uint16_t method    = rd16(p + 10);
        uint32_t comp      = rd32(p + 20);
        uint32_t uncomp    = rd32(p + 24);
        uint16_t name_len  = rd16(p + 28);
        uint16_t extra_len = rd16(p + 30);
        uint16_t cmt_len   = rd16(p + 32);
        uint32_t lfh_off   = rd32(p + 42);

        size_t total_var = (size_t)name_len + extra_len + cmt_len;
        if (cd_off + kCdfhMinSize + total_var > (size_t)cdi.cd_size) break;

        std::string_view name(reinterpret_cast<const char*>(p + kCdfhMinSize), name_len);

        if (name == entry_name) {
            // ZIP64 sentinel guard — skip rather than misinterpret.
            if (comp == 0xFFFFFFFFu || uncomp == 0xFFFFFFFFu) {
                RLOGW("zip: hash_entry_decompressed: ZIP64 entry '%s', skipping", entry_name);
                return false;
            }

            // Resolve body offset via LFH (LFH and CDFH extra fields may differ).
            const uint8_t* lfh = apk.range(lfh_off, kLfhMinSize);
            if (!lfh || rd32(lfh) != kLfhMagic) return false;
            uint16_t lfh_name_len  = rd16(lfh + 26);
            uint16_t lfh_extra_len = rd16(lfh + 28);
            uint64_t body_off = (uint64_t)lfh_off + kLfhMinSize
                                + lfh_name_len + lfh_extra_len;

            // M-2: 32-bit body_off narrowing guard — reject before any size_t cast.
            if (body_off > (uint64_t)apk.size()) return false;
            if ((uint64_t)comp > (uint64_t)apk.size() - body_off) return false;

            if (method == 0 /* STORED */) {
                const uint8_t* body = apk.range((size_t)body_off, (size_t)comp);
                if (!body) return false;
                return sha::sha256(body, (size_t)comp, out32);
            }

            if (method == 8 /* DEFLATED */) {
                // I-2: bound the compressed size symmetrically with the uncomp cap.
                if (comp > kMaxInflateBytes) {
                    RLOGW("zip: hash_entry_decompressed: comp_size %u > limit for '%s'",
                          comp, entry_name);
                    return false;
                }
                if (uncomp > kMaxInflateBytes) {
                    RLOGW("zip: hash_entry_decompressed: uncomp_size %u > limit for '%s'",
                          uncomp, entry_name);
                    return false;
                }

                const uint8_t* comp_body = apk.range((size_t)body_off, (size_t)comp);
                if (!comp_body) return false;

                // I-1: Fixed-buffer streaming inflate + incremental SHA-256.
                // Peak memory: O(64 KiB), independent of entry size.
                constexpr size_t kBufSize = 64u * 1024u;
                uint8_t out_buf[kBufSize];

                sha::Sha256Ctx sha_ctx;
                sha::sha256_init(&sha_ctx);

                z_stream zs{};
                // -MAX_WBITS = raw deflate (no zlib/gzip header).
                if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;

                zs.next_in  = const_cast<Bytef*>(comp_body);
                zs.avail_in = comp;

                size_t total_inflated = 0;
                int ret = Z_OK;

                while (ret != Z_STREAM_END) {
                    zs.next_out  = out_buf;
                    zs.avail_out = (uInt)kBufSize;

                    ret = inflate(&zs, Z_NO_FLUSH);

                    // Guard: no-progress with no pending input → infinite-loop risk.
                    if (ret == Z_BUF_ERROR
                            && zs.avail_out == (uInt)kBufSize
                            && zs.avail_in  == 0) {
                        inflateEnd(&zs);
                        RLOGW("zip: hash_entry_decompressed: inflate no-progress for '%s'",
                              entry_name);
                        return false;
                    }

                    if (ret != Z_OK && ret != Z_STREAM_END) {
                        inflateEnd(&zs);
                        RLOGW("zip: hash_entry_decompressed: inflate ret=%d for '%s'",
                              ret, entry_name);
                        return false;
                    }

                    size_t produced = kBufSize - (size_t)zs.avail_out;
                    total_inflated += produced;
                    if (total_inflated > kMaxInflateBytes) {
                        inflateEnd(&zs);
                        RLOGW("zip: hash_entry_decompressed: inflate exceeded limit for '%s'",
                              entry_name);
                        return false;
                    }

                    sha::sha256_update(&sha_ctx, out_buf, produced);
                }

                inflateEnd(&zs);
                sha::sha256_final(&sha_ctx, out32);
                return true;
            }

            RLOGW("zip: hash_entry_decompressed: unsupported method %u for '%s'",
                  method, entry_name);
            return false;
        }

        cd_off += kCdfhMinSize + total_var;
    }
    return false; // entry not found
}

} // namespace dicore::zip
