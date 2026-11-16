#include "dicore/platform/hex.h"

namespace dicore::hex {

std::string encode(const uint8_t* bytes, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2 * i + 0] = kHex[(bytes[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[bytes[i] & 0xF];
    }
    return out;
}

} // namespace dicore::hex
