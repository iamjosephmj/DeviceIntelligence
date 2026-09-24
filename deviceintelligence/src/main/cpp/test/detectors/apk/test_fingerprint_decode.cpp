// Host test for the fingerprint blob decoder. Cross-implementation vector: the
// blob was produced by the Kotlin FingerprintCodec.encode (GoldenBlobTest) + XOR
// key; this asserts the native fp::decode recovers the exact fields, plus a
// malformed matrix. Build via native-unit-tests.sh.
#include "dicore/detectors/apk/identity/fingerprint_decode.h"
#include "test_fingerprint_data.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    using namespace dicore::fp;

    Fingerprint fp;
    Status st = decode(kFpCipher, kFpCipherLen, kFpKey, kFpKeyLen, &fp);
    assert(st == Status::kOk);
    assert(fp.schema_version == 3);
    assert(fp.plugin_version == "golden");
    assert(fp.variant_name == "release");
    assert(fp.application_id == "tech.thessemaj.deviceintelligence.golden");
    assert(fp.signer_cert_sha256.size() == 1 && fp.signer_cert_sha256[0] == "ab");
    assert(fp.expected_source_dir_prefix == "/data/app/");
    assert(fp.ignored_entry_prefixes.size() == 1 && fp.ignored_entry_prefixes[0] == "META-INF/");
    // v3 bundle-mode fields (the whole reason this vector exists)
    assert(fp.bundle_mode == true);
    assert(fp.bundle_entry_hashes.size() == 2);
    bool sawDex = false, sawLib = false;
    for (auto& kv : fp.bundle_entry_hashes) {
        if (kv.first == "classes.dex" && kv.second == "11") sawDex = true;
        if (kv.first == "lib/arm64-v8a/libdicore.so" && kv.second == "22") sawLib = true;
    }
    assert(sawDex && sawLib);
    // canonical_digest is stable + non-empty
    assert(!canonical_digest(fp).empty());

    // ---- malformed matrix ----
    // clen < 4 -> kCorrupt
    { Fingerprint f; assert(decode(kFpCipher, 3, kFpKey, kFpKeyLen, &f) == Status::kCorrupt); }
    // corrupt a magic byte (first plaintext u32) -> kBadMagic
    {
        std::vector<uint8_t> bad(kFpCipher, kFpCipher + kFpCipherLen);
        bad[0] ^= 0xFF; Fingerprint f;
        assert(decode(bad.data(), bad.size(), kFpKey, kFpKeyLen, &f) == Status::kBadMagic);
    }
    // truncation sweep: every proper prefix decodes to a non-kOk status, no crash.
    for (size_t k = 4; k < kFpCipherLen; ++k) {
        Fingerprint f; Status s = decode(kFpCipher, k, kFpKey, kFpKeyLen, &f);
        assert(s != Status::kOk);
    }

    std::printf("test_fingerprint_decode OK\n");
    return 0;
}
