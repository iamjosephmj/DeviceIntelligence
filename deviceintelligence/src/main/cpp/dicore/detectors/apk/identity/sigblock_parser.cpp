#include "dicore/detectors/apk/identity/sigblock_parser.h"

#include "dicore/platform/hex.h"
#include "dicore/platform/log.h"
#include "dicore/crypto/sha256.h"

#include <cstring>

namespace dicore::sigblock {

namespace {

constexpr uint32_t kIdV2  = 0x7109871au;
constexpr uint32_t kIdV3  = 0xf05368c0u;

// 16-byte ASCII tag immediately preceding the central directory.
constexpr char kSigBlockMagic[16] = {
        'A','P','K',' ','S','i','g',' ',
        'B','l','o','c','k',' ','4','2',
};

inline uint32_t rd32(const uint8_t* p) {
    return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24));
}

inline uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

// Cursor over a length-bounded byte range, with safe consumers that
// fail-soft instead of overrunning.
struct Cursor {
    const uint8_t* p;
    const uint8_t* end;

    bool remaining(size_t n) const { return (size_t)(end - p) >= n; }

    bool take_u32(uint32_t* out) {
        if (!remaining(4)) return false;
        *out = rd32(p);
        p += 4;
        return true;
    }
    bool take_u64(uint64_t* out) {
        if (!remaining(8)) return false;
        *out = rd64(p);
        p += 8;
        return true;
    }
    bool take_bytes(size_t n, const uint8_t** out) {
        if (!remaining(n)) return false;
        *out = p;
        p += n;
        return true;
    }
    // Reads a u32-length-prefixed sub-cursor; on success advances past it.
    bool take_u32_lp(Cursor* sub) {
        uint32_t len = 0;
        if (!take_u32(&len)) return false;
        if (!remaining(len)) return false;
        sub->p   = p;
        sub->end = p + len;
        p += len;
        return true;
    }
};

// Locate APK Signing Block. On success: out_block_start/out_block_size
// describe the block including the leading u64 "size_of_block".
bool locate_block(const ApkMap& apk,
                  const zip::CentralDirInfo& cdi,
                  size_t* out_block_start,
                  size_t* out_block_size) {
    if (!cdi.present || cdi.cd_offset < 32) return false;

    const uint8_t* magic_p = apk.range((size_t)cdi.cd_offset - 16, 16);
    if (!magic_p) return false;
    if (std::memcmp(magic_p, kSigBlockMagic, 16) != 0) {
        // No signing block present (jar-signed v1 only, or unsigned).
        return false;
    }

    const uint8_t* size_at_bottom_p = apk.range((size_t)cdi.cd_offset - 24, 8);
    if (!size_at_bottom_p) return false;
    uint64_t size_excluding_top = rd64(size_at_bottom_p);

    // Block on disk is size_excluding_top + 8 (for the leading u64 size).
    if (size_excluding_top + 8 > cdi.cd_offset) return false;
    size_t block_start = (size_t)cdi.cd_offset - (size_t)(size_excluding_top + 8);

    const uint8_t* size_at_top_p = apk.range(block_start, 8);
    if (!size_at_top_p) return false;
    if (rd64(size_at_top_p) != size_excluding_top) {
        RLOGW("sigblock: top/bottom size mismatch (top=%llu bot=%llu)",
              (unsigned long long)rd64(size_at_top_p),
              (unsigned long long)size_excluding_top);
        return false;
    }

    *out_block_start = block_start;
    *out_block_size  = (size_t)(size_excluding_top + 8);
    return true;
}

// Walk id-value pairs and call sink for each. Each pair's value cursor
// covers exactly the value bytes (excluding the u32 id and u64 length).
template <typename Sink>
void for_each_pair(const uint8_t* pairs_begin, const uint8_t* pairs_end,
                   Sink sink) {
    Cursor c { pairs_begin, pairs_end };
    while (c.remaining(12)) {
        uint64_t pair_len = 0;
        if (!c.take_u64(&pair_len)) break;
        if (!c.remaining((size_t)pair_len)) break;
        const uint8_t* pair_end = c.p + pair_len;

        uint32_t id = 0;
        if (!c.take_u32(&id)) break;
        size_t value_len = (size_t)pair_len - 4;

        Cursor value { c.p, c.p + value_len };
        sink(id, value);
        c.p = pair_end;
    }
}

// Parse a single v2/v3 schema value to extract certificate DER bytes.
// V2 layout: [signers_seq] -> for each signer: [signed_data_lp][signatures_lp][public_key_lp]
//   signed_data: [digests_seq][certs_seq][additional_attrs_seq]
// V3 layout: same, with min/max SDK appended after public_key. The
// certificate path through signed_data is identical.
bool parse_signers(Cursor v, std::vector<std::string>* out_hex_hashes) {
    Cursor signers_seq;
    if (!v.take_u32_lp(&signers_seq)) return false;

    while (signers_seq.remaining(4)) {
        Cursor signer;
        if (!signers_seq.take_u32_lp(&signer)) return false;

        Cursor signed_data;
        if (!signer.take_u32_lp(&signed_data)) return false;

        // Inside signed_data: [digests][certs][additional_attrs]
        Cursor digests_seq;
        if (!signed_data.take_u32_lp(&digests_seq)) return false;
        // Skip digests; we don't need them for cert hashing.

        Cursor certs_seq;
        if (!signed_data.take_u32_lp(&certs_seq)) return false;

        // Walk certificates, each is u32-length-prefixed DER.
        while (certs_seq.remaining(4)) {
            Cursor cert;
            if (!certs_seq.take_u32_lp(&cert)) return false;

            uint8_t md[sha::kDigestLen];
            if (!sha::sha256(cert.p, (size_t)(cert.end - cert.p), md)) {
                RLOGE("sigblock: sha256 failed on signer cert");
                continue;
            }
            out_hex_hashes->emplace_back(hex::encode(md, sha::kDigestLen));
        }
    }
    return true;
}

} // namespace

bool extract_signer_certs(const ApkMap& apk,
                          const zip::CentralDirInfo& cdi,
                          SignerCerts* out) {
    if (!out) return false;
    *out = {};

    size_t block_start = 0, block_size = 0;
    if (!locate_block(apk, cdi, &block_start, &block_size)) return false;

    // Pairs region = [block_start + 8, block_start + block_size - 24)
    // (8 = leading size, 24 = trailing size + magic).
    if (block_size < 32) return false;
    const uint8_t* pairs = apk.range(block_start + 8, block_size - 32);
    if (!pairs) return false;

    std::vector<std::string> v2_hashes;
    std::vector<std::string> v3_hashes;

    for_each_pair(pairs, pairs + (block_size - 32),
                  [&](uint32_t id, Cursor value) {
                      if (id == kIdV3) {
                          parse_signers(value, &v3_hashes);
                      } else if (id == kIdV2) {
                          parse_signers(value, &v2_hashes);
                      }
                  });

    if (!v3_hashes.empty()) {
        out->cert_sha256_hex = std::move(v3_hashes);
        out->source          = SignerCerts::Source::kV3;
        return true;
    }
    if (!v2_hashes.empty()) {
        out->cert_sha256_hex = std::move(v2_hashes);
        out->source          = SignerCerts::Source::kV2;
        return true;
    }
    return false;
}

} // namespace dicore::sigblock
