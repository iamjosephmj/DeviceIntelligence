#include "dicore/crypto/fp_pepper.h"

#include "dicore/crypto/sha256.h"

#include <cstring>
#include <vector>

namespace dicore::crypto {

namespace {
constexpr char kInfo[] = "intel-fp-pepper-v1";
constexpr size_t kInfoLen = sizeof(kInfo) - 1;   // derive, never hardcode
} // namespace

void fp_pepper(const LicenceKey& key, uint8_t out[32]) {
    uint8_t buf[kInfoLen + 32];
    std::memcpy(buf, kInfo, kInfoLen);
    std::memcpy(buf + kInfoLen, key.pubkey, 32);
    if (!dicore::sha::sha256(buf, sizeof(buf), out)) std::memset(out, 0, 32);
}

bool fp_hash(const uint8_t* pepper, const std::string& value, std::string* out_hex) {
    if (pepper == nullptr || out_hex == nullptr || value.empty()) return false;
    std::vector<uint8_t> buf(32 + value.size());
    std::memcpy(buf.data(), pepper, 32);
    std::memcpy(buf.data() + 32, value.data(), value.size());
    uint8_t d[32];
    if (!dicore::sha::sha256(buf.data(), buf.size(), d)) return false;
    static const char* hexd = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (uint8_t b : d) { s.push_back(hexd[(b >> 4) & 0xf]); s.push_back(hexd[b & 0xf]); }
    *out_hex = s;
    return true;
}

} // namespace dicore::crypto
