#include "dicore/detectors/apk/identity/fingerprint_decode.h"

#include <algorithm>
#include <cstring>

// Byte-faithful port of FingerprintCodec.kt's decoder + FingerprintDecoder.kt's
// XOR step. Pure (no JNI/platform deps) so it fuzzes standalone (§4.4).

namespace dicore::fp {
namespace {

constexpr uint32_t kMagic = 0x52615370u;  // 'RaSp'
constexpr int kMinFormat = 1;
constexpr int kMaxFormat = 3;

// Hard caps (§4.3) — a benign blob is well under these; anything larger is
// treated as corrupt rather than walked/allocated.
constexpr size_t kMaxBlob = 1u << 20;   // 1 MB decrypted
constexpr uint32_t kMaxCount = 100000;  // per-list element cap

// Big-endian, bounds-checked cursor over the decrypted plaintext, matching Java
// DataInputStream (readInt/readLong/readUnsignedShort/readUTF).
class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), n_(n), pos_(0), ok_(true) {}
    bool ok() const { return ok_; }

    uint32_t u32() {
        if (!need(4)) return 0;
        uint32_t v = ((uint32_t)p_[pos_] << 24) | ((uint32_t)p_[pos_ + 1] << 16) |
                     ((uint32_t)p_[pos_ + 2] << 8) | (uint32_t)p_[pos_ + 3];
        pos_ += 4;
        return v;
    }

    // Java writeBoolean: a single byte, 0 = false / non-zero = true.
    bool boolean() {
        if (!need(1)) return false;
        return p_[pos_++] != 0;
    }
    void skip_i64() { need(8) && (pos_ += 8, true); }

    // Java writeUTF: 2-byte big-endian length, then that many UTF-8 bytes. We
    // pass the bytes through verbatim (no modified-UTF8 surrogate handling — the
    // encoder only writes ASCII hex/package/path strings, identical on both sides).
    std::string utf() {
        if (!need(2)) return {};
        uint32_t len = ((uint32_t)p_[pos_] << 8) | (uint32_t)p_[pos_ + 1];
        pos_ += 2;
        if (!need(len)) return {};
        std::string s(reinterpret_cast<const char*>(p_ + pos_), len);
        pos_ += len;
        return s;
    }

    // A non-negative, capped element count (Kotlin readNonNegative + sanity).
    uint32_t count() {
        uint32_t v = u32();
        if (!ok_) return 0;
        if (v > kMaxCount) { ok_ = false; return 0; }
        return v;
    }

    bool at_end() const { return pos_ == n_; }

private:
    bool need(size_t k) {
        if (!ok_) return false;
        if (k > n_ - pos_) { ok_ = false; return false; }
        return true;
    }
    const uint8_t* p_;
    size_t n_;
    size_t pos_;
    bool ok_;
};

void read_string_list(Reader& r, std::vector<std::string>* out) {
    uint32_t n = r.count();
    if (!r.ok()) return;
    out->reserve(n < 64 ? n : 64);
    for (uint32_t i = 0; i < n && r.ok(); ++i) out->push_back(r.utf());
}

}  // namespace

Status decode(const uint8_t* cipher, size_t clen,
              const uint8_t* key, size_t klen, Fingerprint* out) {
    if (cipher == nullptr || key == nullptr || klen == 0) return Status::kCorrupt;
    if (clen < 8 || clen > kMaxBlob) {
        // Too short to hold magic+version, or implausibly large.
        return clen < 4 ? Status::kCorrupt : Status::kBadMagic;
    }

    // XOR-decrypt with the cycling key (FingerprintDecoder.kt).
    std::vector<uint8_t> plain(clen);
    for (size_t i = 0; i < clen; ++i) plain[i] = cipher[i] ^ key[i % klen];

    Reader r(plain.data(), plain.size());
    uint32_t magic = r.u32();
    if (!r.ok()) return Status::kCorrupt;
    if (magic != kMagic) return Status::kBadMagic;

    uint32_t format = r.u32();
    if (!r.ok()) return Status::kCorrupt;
    if ((int)format < kMinFormat || (int)format > kMaxFormat) return Status::kFormatMismatch;

    Fingerprint fp;
    fp.schema_version = (int)r.u32();
    r.skip_i64();                       // builtAtEpochMs (unused at runtime)
    fp.plugin_version = r.utf();
    fp.variant_name = r.utf();
    fp.application_id = r.utf();

    read_string_list(r, &fp.signer_cert_sha256);

    uint32_t entry_count = r.count();
    for (uint32_t i = 0; i < entry_count && r.ok(); ++i) {
        std::string name = r.utf();
        std::string hash = r.utf();
        fp.entries.emplace_back(std::move(name), std::move(hash));
    }

    read_string_list(r, &fp.ignored_entries);
    read_string_list(r, &fp.ignored_entry_prefixes);
    fp.expected_source_dir_prefix = r.utf();
    read_string_list(r, &fp.expected_installer_whitelist);

    if (format >= 2) {
        // nativeLibInventoryByAbi: abi -> [filenames]. Parsed and carried in the meta
        // row (field 5), but no longer ENFORCED at runtime: its consumer was the
        // lib_inventory scanner, removed in #17 as redundant with INTEL_0035. Kept on the
        // wire for meta/back-compat stability. Like nativeLibHashesByAbi below.
        uint32_t abi_inv = r.count();
        for (uint32_t i = 0; i < abi_inv && r.ok(); ++i) {
            std::string abi = r.utf();
            std::vector<std::string> files;
            read_string_list(r, &files);
            fp.native_lib_inventory_by_abi.emplace_back(std::move(abi), std::move(files));
        }
        // nativeLibHashesByAbi: abi -> {filename -> sha256} (parsed to advance the
        // cursor; not consumed at runtime).
        uint32_t abi_fh = r.count();
        for (uint32_t i = 0; i < abi_fh && r.ok(); ++i) {
            (void)r.utf();  // abi
            uint32_t fc = r.count();
            for (uint32_t j = 0; j < fc && r.ok(); ++j) {
                (void)r.utf();  // filename
                (void)r.utf();  // sha256
            }
        }
        // dicoreTextSha256ByAbi: abi -> sha256
        uint32_t abi_text = r.count();
        for (uint32_t i = 0; i < abi_text && r.ok(); ++i) {
            std::string abi = r.utf();
            std::string sha = r.utf();
            fp.dicore_text_sha256_by_abi.emplace_back(std::move(abi), std::move(sha));
        }
    }

    if (format >= 3) {
        // v3 tail: bundleMode flag + bundle entry decompressed-hash map.
        fp.bundle_mode = r.boolean();
        uint32_t bundle_count = r.count();
        for (uint32_t i = 0; i < bundle_count && r.ok(); ++i) {
            std::string name = r.utf();
            std::string sha = r.utf();
            fp.bundle_entry_hashes.emplace_back(std::move(name), std::move(sha));
        }
    }

    if (!r.ok()) return Status::kCorrupt;
    *out = std::move(fp);
    return Status::kOk;
}

namespace {
void append_list(std::string& d, const char* tag, std::vector<std::string> v) {
    // Canonicalize order so map/list iteration differences don't cause false
    // parity divergences (the runtime doesn't depend on order).
    std::sort(v.begin(), v.end());
    d += tag;
    d += '[';
    for (const auto& s : v) { d += s; d += ','; }
    d += "]\n";
}
}  // namespace

std::string canonical_digest(const Fingerprint& fp) {
    std::string d;
    d += "schema=" + std::to_string(fp.schema_version) + "\n";
    d += "plugin=" + fp.plugin_version + "\n";
    d += "variant=" + fp.variant_name + "\n";
    d += "app=" + fp.application_id + "\n";
    d += "srcdir=" + fp.expected_source_dir_prefix + "\n";
    append_list(d, "signers", fp.signer_cert_sha256);
    append_list(d, "ignored", fp.ignored_entries);
    append_list(d, "prefixes", fp.ignored_entry_prefixes);
    append_list(d, "installers", fp.expected_installer_whitelist);
    {
        std::vector<std::string> e;
        e.reserve(fp.entries.size());
        for (const auto& kv : fp.entries) e.push_back(kv.first + "=" + kv.second);
        append_list(d, "entries", std::move(e));
    }
    {
        std::vector<std::string> t;
        for (const auto& kv : fp.dicore_text_sha256_by_abi) t.push_back(kv.first + "=" + kv.second);
        append_list(d, "abitext", std::move(t));
    }
    {
        std::vector<std::string> inv;
        for (auto kv : fp.native_lib_inventory_by_abi) {
            std::sort(kv.second.begin(), kv.second.end());
            std::string row = kv.first + ":";
            for (const auto& f : kv.second) { row += f; row += ','; }
            inv.push_back(row);
        }
        append_list(d, "abiinv", std::move(inv));
    }
    d += "bundle=" + std::string(fp.bundle_mode ? "1" : "0") + "\n";
    {
        std::vector<std::string> b;
        b.reserve(fp.bundle_entry_hashes.size());
        for (const auto& kv : fp.bundle_entry_hashes) b.push_back(kv.first + "=" + kv.second);
        append_list(d, "bundleentries", std::move(b));
    }
    return d;
}

}  // namespace dicore::fp
