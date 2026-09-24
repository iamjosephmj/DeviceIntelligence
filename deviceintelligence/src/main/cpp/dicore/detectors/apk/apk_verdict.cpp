// apk_integrity_jni.cpp — native integrity.apk verdict (spec 04 / S4).
//
// The whole APK-integrity DECISION now lives in C++: decode the baked fingerprint
// (fingerprint_decode), hash the live APK (zip_parser + sigblock_parser over an
// ApkMap), diff, and emit ready-to-marshal Finding records. Kotlin only ACQUIRES
// the framework values it must (the asset bytes via ZipFile, the assembled key via
// reflection, the installer package via PackageManager, sourceDir, the running
// ABI) and marshals the records. No comparison / severity decision in the JVM.
//
// Faithful port of the former ApkIntegrityDetector diff. Records are US(0x1f)-
// framed: kind \x1f SEVERITY \x1f subject \x1f message \x1f k=v \x1f ...
// The first record is a "__meta" row carrying the scalars Kotlin still needs
// (variant/plugin for AppContext) + the per-ABI G2 baseline. Field 4 is the text
// hash, which the native path installs via set_expected_text_hash (orchestrate.cpp)
// and which initNativeIntegrity consumes. Field 5 is the per-ABI .so inventory: it
// is still emitted for wire/meta stability, but has NO runtime consumer since the
// lib_inventory scanner it fed (set_expected_so_inventory) was removed — see #8/#17.

#include "dicore/detectors/apk/container/apkmap.h"
#include "dicore/detectors/apk/identity/fingerprint_decode.h"
#include "dicore/platform/framework_shim.h"  // split_source_dirs() for bundle mode
#include "dicore/platform/obf.h"  // DI_OBF_MAX
#include "dicore/crypto/sha256.h"
#include "dicore/detectors/apk/identity/sigblock_parser.h"
#include "dicore/detectors/apk/container/zip_parser.h"

#include <jni.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace dicore {
namespace {

constexpr char kFS = '\x1f';

std::string rec(const char* kind, const char* sev, const std::string& subject,
                const std::string& msg, const std::vector<std::string>& details) {
    std::string r = kind;
    r += kFS; r += sev;
    r += kFS; r += subject;
    r += kFS; r += msg;
    for (const auto& d : details) { r += kFS; r += d; }
    return r;
}

std::string join(const std::vector<std::string>& v, char sep) {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) { if (i) s += sep; s += v[i]; }
    return s;
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

// env-KEK fingerprint-key derivation, byte-identical to the plugin's
// InstrumentApkTask.deriveFpKey: K = SHA256(seed XOR SHA256(phrase)). The phrase
// is embedded ONLY here (OLLVM string-encrypted in obfuscated builds) + in the
// plugin; the per-build seed is shipped in the blob. So no key material is in the
// dex — this replaced the KeyChunks/KeyAssembler reflection path.
DI_OBF_MAX
bool fp_derive_key(const uint8_t* seed, uint8_t* out /*32*/) {
    if (!sha::ensure_initialized()) return false;
    const char* phrase = "dicore-fpkey-mix-v1";
    uint8_t mix[sha::kDigestLen];
    if (!sha::sha256(phrase, std::strlen(phrase), mix)) return false;
    uint8_t eff[32];
    for (int i = 0; i < 32; ++i) eff[i] = (uint8_t)(seed[i] ^ mix[i]);
    return sha::sha256(eff, 32, out);
}

}  // namespace

// Native integrity.apk verdict core (shared by the Kotlin-driven JNI and the
// native orchestrator): decode the baked fingerprint, hash the live APK, diff,
// and return the Finding records (first row = __meta; __status row on a
// fail-open path). All inputs are plain acquisition values.
std::vector<std::string> apk_verdict_records(const std::string& apkPath,
                                             const std::vector<uint8_t>& asset,
                                             const std::string& installer,
                                             const std::string& abi) {
    std::vector<std::string> out;
    if (apkPath.empty() || asset.empty()) {
        out.push_back(std::string("__status") + kFS + "BAD_INPUT");
        return out;
    }

    // ---- decode the baked fingerprint ---------------------------------------
    // Blob layout (spec 04): seed(32) || ciphertext. Derive the XOR key from the
    // seed + the embedded env-KEK phrase; the key is never shipped.
    constexpr size_t kSeedLen = 32;
    if (asset.size() < kSeedLen + 4) {
        out.push_back(rec("fingerprint_corrupt", "HIGH", "",
                          "Fingerprint blob is structurally malformed", {}));
        return out;
    }
    uint8_t key[32];
    if (!fp_derive_key(asset.data(), key)) {
        out.push_back(std::string("__status") + kFS + "APK_UNREADABLE");  // no crypto -> fail-open
        return out;
    }

    fp::Fingerprint fp;
    fp::Status st = fp::decode(asset.data() + kSeedLen, asset.size() - kSeedLen, key, kSeedLen, &fp);
    if (st != fp::Status::kOk) {
        switch (st) {
            case fp::Status::kBadMagic:
                out.push_back(rec("fingerprint_bad_magic", "CRITICAL", "",
                                  "Fingerprint blob has wrong magic — likely re-encrypted with a different key", {}));
                break;
            case fp::Status::kFormatMismatch:
                out.push_back(std::string("__status") + kFS + "FORMAT_SKEW");
                break;
            default:
                out.push_back(rec("fingerprint_corrupt", "HIGH", "",
                                  "Fingerprint blob is structurally malformed", {}));
        }
        return out;
    }

    // ---- meta row: scalars for AppContext + G2 baseline for the running ABI --
    std::string textHash;
    for (const auto& kv : fp.dicore_text_sha256_by_abi)
        if (kv.first == abi) { textHash = kv.second; break; }
    std::vector<std::string> soList;
    for (const auto& kv : fp.native_lib_inventory_by_abi)
        if (kv.first == abi) { soList = kv.second; break; }
    out.push_back(std::string("__meta") + kFS + std::to_string(fp.schema_version) + kFS +
                  fp.variant_name + kFS + fp.plugin_version + kFS + textHash + kFS + join(soList, ','));

    // ---- bundle mode (App Bundle): decompressed dex/.so diff across splits ---
    // Play re-encodes/re-signs the split APKs, so we cannot byte-diff the
    // compressed entry set or pin a single signer the way APK mode does.
    // Instead: (1) the installed signer must be a MEMBER of the baked allow-set
    // (keystore signer ∪ Play pins), and (2) every baked entry's DECOMPRESSED
    // body must match, searched across base ∪ splitSourceDirs. We do NOT run the
    // compressed entry-set / added-entry diff here.
    if (fp.bundle_mode) {
        ApkMap base;
        zip::CentralDirInfo bcdi;
        if (!base.open(apkPath.c_str()) || !zip::find_central_directory(base, &bcdi)) {
            out.push_back(std::string("__status") + kFS + "APK_UNREADABLE");
            return out;
        }

        // (1) signer membership (skip entirely if no allow-set was baked).
        if (!fp.signer_cert_sha256.empty()) {
            sigblock::SignerCerts certs;
            sigblock::extract_signer_certs(base, bcdi, &certs);
            for (const auto& obs : certs.cert_sha256_hex) {
                bool ok = false;
                for (const auto& allow : fp.signer_cert_sha256) if (allow == obs) { ok = true; break; }
                if (!ok) {
                    out.push_back(rec("apk_signer_mismatch", "CRITICAL", "",
                                      "Installed signer not in the baked allow-set (bundle mode)",
                                      {"observed=" + obs, "allowed=" + join(fp.signer_cert_sha256, ',')}));
                }
            }
        }

        // (2) candidate APK paths: base sourceDir + every split.
        std::vector<std::string> apks;
        apks.push_back(apkPath);
        for (auto& s : split_source_dirs()) apks.push_back(s);

        for (const auto& kv : fp.bundle_entry_hashes) {
            bool found = false;
            std::string observed;
            for (const auto& p : apks) {
                ApkMap m;
                if (!m.open(p.c_str())) continue;
                zip::CentralDirInfo c;
                if (!zip::find_central_directory(m, &c)) continue;
                if (zip::hash_entry_decompressed(m, c, kv.first, &observed)) { found = true; break; }
            }
            if (!found) {
                out.push_back(rec("apk_entry_removed", "HIGH", kv.first,
                                  "Baked bundle entry not found across base+splits",
                                  {"expected=" + kv.second}));
            } else if (observed != kv.second) {
                out.push_back(rec("apk_entry_modified", "CRITICAL", kv.first,
                                  "Bundle entry bytes differ from build time",
                                  {"expected=" + kv.second, "observed=" + observed}));
            }
        }
        return out;
    }

    // ---- live APK: signer certs + entry hashes ------------------------------
    ApkMap apk;
    if (!apk.open(apkPath.c_str())) {
        out.push_back(std::string("__status") + kFS + "APK_UNREADABLE");
        return out;
    }
    zip::CentralDirInfo cdi;
    if (!zip::find_central_directory(apk, &cdi)) {
        out.push_back(std::string("__status") + kFS + "APK_UNREADABLE");
        return out;
    }

    // signer set-diff (order-independent), mirroring Kotlin's Set comparison.
    sigblock::SignerCerts certs;
    sigblock::extract_signer_certs(apk, cdi, &certs);
    {
        std::vector<std::string> expected = fp.signer_cert_sha256, observed = certs.cert_sha256_hex;
        std::vector<std::string> e2 = expected, o2 = observed;
        std::sort(e2.begin(), e2.end()); e2.erase(std::unique(e2.begin(), e2.end()), e2.end());
        std::sort(o2.begin(), o2.end()); o2.erase(std::unique(o2.begin(), o2.end()), o2.end());
        if (e2 != o2) {
            out.push_back(rec("apk_signer_mismatch", "CRITICAL", "",
                              "APK signer cert(s) differ from the build-time baked set",
                              {"expected=" + join(expected, ','), "observed=" + join(observed, ',')}));
        }
    }

    // source-dir prefix
    if (!fp.expected_source_dir_prefix.empty() && !starts_with(apkPath, fp.expected_source_dir_prefix)) {
        out.push_back(rec("apk_source_dir_unexpected", "MEDIUM", apkPath,
                          "Installed APK lives outside the expected path prefix",
                          {"expected_prefix=" + fp.expected_source_dir_prefix, "observed_path=" + apkPath}));
    }

    // installer whitelist
    if (!fp.expected_installer_whitelist.empty()) {
        bool ok = false;
        for (const auto& w : fp.expected_installer_whitelist) if (w == installer && !installer.empty()) { ok = true; break; }
        if (!ok) {
            out.push_back(rec("installer_not_whitelisted", "MEDIUM", installer,
                              "Installer package is not in the baked whitelist",
                              {"whitelist=" + join(fp.expected_installer_whitelist, ','),
                               "observed_installer=" + (installer.empty() ? std::string("<null>") : installer)}));
        }
    }

    // entry-level diff (filter live entries through the baked ignore rules)
    std::unordered_map<std::string, std::string> filtered;
    zip::hash_all_entries(apk, cdi, [&](const zip::EntryHash& e) {
        const std::string& name = e.name;
        for (const auto& ig : fp.ignored_entries) if (ig == name) return;
        for (const auto& pre : fp.ignored_entry_prefixes) if (starts_with(name, pre)) return;
        filtered[name] = e.sha256_hex;
    });
    std::unordered_map<std::string, std::string> expectedEntries;
    for (const auto& kv : fp.entries) expectedEntries[kv.first] = kv.second;

    for (const auto& kv : fp.entries) {
        auto it = filtered.find(kv.first);
        if (it == filtered.end()) {
            out.push_back(rec("apk_entry_removed", "HIGH", kv.first,
                              "APK entry was present at build time but is missing at runtime",
                              {"expected_hash=" + kv.second}));
        } else if (it->second != kv.second) {
            out.push_back(rec("apk_entry_modified", "CRITICAL", kv.first,
                              "APK entry exists but its bytes differ from build time",
                              {"expected_hash=" + kv.second, "observed_hash=" + it->second}));
        }
    }
    for (const auto& kv : filtered) {
        if (expectedEntries.find(kv.first) == expectedEntries.end()) {
            out.push_back(rec("apk_entry_added", "HIGH", kv.first,
                              "APK entry exists at runtime but wasn't present at build time",
                              {"observed_hash=" + kv.second}));
        }
    }

    return out;
}

}  // namespace dicore
