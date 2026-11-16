#include "dicore/platform/framework_shim.h"
#include "dicore/core/verdict_cores.h"
#include "dicore/crypto/sha256.h"
#include "dicore/platform/obf.h"             // DI_OBF_ATTEST

#include <pthread.h>
#include <algorithm>
#include <cstring>
#include <vector>

// Offline certificate-revocation check against Google's attestation status list
// (https://android.googleapis.com/attestation/status), baked weekly into an
// encrypted asset and read here. A leaked keybox that Google has revoked is a
// definitive spoofer signal even when the chain otherwise verifies and reports a
// clean boot state. The asset is XOR-encrypted with a SHA-256 keystream keyed by
// SHA256(phrase) — see tools/crl/pack_crl.py (the build/CI packer). Encryption is
// tamper-resistance, not secrecy (the list is public): it stops a trivial strip/
// replace of the revocation data. Fail-open throughout (no asset / bad key /
// corrupt -> empty set -> never revokes).

namespace dicore {
namespace {

constexpr char kCrlPhrase[] = "dicore-crl-key-v1";  // DI_OBF cse-encrypts this
constexpr unsigned char kMagic[4] = {'D', 'C', 'R', 'L'};

pthread_once_t g_once = PTHREAD_ONCE_INIT;
std::vector<std::vector<uint8_t>>* g_serials = nullptr;  // revoked, minimal BE, sorted

// SHA-256 keystream XOR in place (matches pack_crl.py).
void crl_decrypt(std::vector<uint8_t>& buf) {
    uint8_t key[32];
    sha::sha256(kCrlPhrase, sizeof(kCrlPhrase) - 1, key);
    uint8_t in[36];
    memcpy(in, key, 32);
    uint8_t ks[32];
    uint32_t block = 0;
    for (size_t off = 0; off < buf.size(); off += 32, ++block) {
        in[32] = (uint8_t)(block);
        in[33] = (uint8_t)(block >> 8);
        in[34] = (uint8_t)(block >> 16);
        in[35] = (uint8_t)(block >> 24);
        sha::sha256(in, sizeof(in), ks);
        for (size_t i = 0; i < 32 && off + i < buf.size(); ++i) buf[off + i] ^= ks[i];
    }
}

DI_OBF_ATTEST __attribute__((noinline))
void crl_load() {
    g_serials = new std::vector<std::vector<uint8_t>>();
    std::vector<uint8_t> blob = fw_crl_asset();
    if (blob.size() < 9) return;
    crl_decrypt(blob);
    if (memcmp(blob.data(), kMagic, 4) != 0 || blob[4] != 1) return;  // bad key/corrupt -> empty
    uint32_t count = (uint32_t)blob[5] | ((uint32_t)blob[6] << 8) |
                     ((uint32_t)blob[7] << 16) | ((uint32_t)blob[8] << 24);
    size_t p = 9;
    for (uint32_t i = 0; i < count && p < blob.size(); ++i) {
        uint8_t n = blob[p++];
        if (n == 0 || p + n > blob.size()) break;
        g_serials->emplace_back(blob.begin() + p, blob.begin() + p + n);
        p += n;
    }
    std::sort(g_serials->begin(), g_serials->end());
}

// Strip leading zero bytes -> minimal big-endian (matches the packer + lets an
// a DER serial, which may carry a leading 0x00 sign byte, compare equal).
std::vector<uint8_t> minimal_be(const uint8_t* p, size_t n) {
    size_t i = 0;
    while (i + 1 < n && p[i] == 0) ++i;
    return std::vector<uint8_t>(p + i, p + n);
}

}  // namespace

// True if [serial] (raw DER integer bytes) is in the revoked set. Fail-open: an
// unavailable / corrupt list never revokes.
DI_OBF_ATTEST
bool crl_is_revoked(const uint8_t* serial, size_t len) {
    if (serial == nullptr || len == 0) return false;
    pthread_once(&g_once, crl_load);
    if (g_serials == nullptr || g_serials->empty()) return false;
    return std::binary_search(g_serials->begin(), g_serials->end(), minimal_be(serial, len));
}

}  // namespace dicore
