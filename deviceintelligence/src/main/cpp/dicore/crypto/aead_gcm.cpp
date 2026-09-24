#include "dicore/crypto/aead_gcm.h"

#include "dicore/crypto/aes_core.h"

#include <cstring>

namespace dicore::crypto {
namespace {

// Constant-time GF(2^128) multiply per SP 800-38D (bit-by-bit, no tables).
// out = X • Y, all 16-byte big-endian blocks. out may alias neither X nor Y.
void gf_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16]) {
    uint8_t Z[16] = {0};
    uint8_t V[16];
    std::memcpy(V, Y, 16);
    for (int i = 0; i < 128; ++i) {
        // bit i of X, MSB-first
        uint8_t bit = (X[i >> 3] >> (7 - (i & 7))) & 1;
        uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(bit));
        for (int j = 0; j < 16; ++j) Z[j] ^= V[j] & mask;
        // V >>= 1 across the whole 128-bit big-endian value; reduce if LSB was set
        uint8_t lsb = V[15] & 1;
        for (int j = 15; j > 0; --j) V[j] = static_cast<uint8_t>((V[j] >> 1) | (V[j - 1] << 7));
        V[0] >>= 1;
        uint8_t rmask = static_cast<uint8_t>(-static_cast<int8_t>(lsb));
        V[0] ^= 0xe1 & rmask;
    }
    std::memcpy(out, Z, 16);
}

void ghash_blocks(const uint8_t H[16], uint8_t X[16], const uint8_t* data, size_t len) {
    uint8_t block[16];
    size_t off = 0;
    while (off < len) {
        size_t n = (len - off < 16) ? (len - off) : 16;
        std::memset(block, 0, 16);
        std::memcpy(block, data + off, n);          // zero-pad the final partial block
        for (int j = 0; j < 16; ++j) X[j] ^= block[j];
        uint8_t tmp[16];
        gf_mul(X, H, tmp);
        std::memcpy(X, tmp, 16);
        off += n;
    }
}

void put_u64_be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
}

void inc32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; --i) { if (++ctr[i] != 0) break; }
}

// GCTR: keystream = AES(counter), counter inc32 per block; out = in ^ keystream.
void gctr(const uint8_t rk[kAes256RoundKeyBytes], uint8_t counter[16],
          const uint8_t* in, size_t len, uint8_t* out) {
    uint8_t ks[16];
    size_t off = 0;
    while (off < len) {
        aes256_encrypt_block(rk, counter, ks);
        inc32(counter);
        size_t n = (len - off < 16) ? (len - off) : 16;
        for (size_t j = 0; j < n; ++j) out[off + j] = in[off + j] ^ ks[j];
        off += n;
    }
}

void compute_tag(const uint8_t rk[kAes256RoundKeyBytes], const uint8_t H[16],
                 const uint8_t J0[16], const uint8_t* aad, size_t aad_len,
                 const uint8_t* ct, size_t ct_len, uint8_t tag[16]) {
    uint8_t X[16] = {0};
    ghash_blocks(H, X, aad, aad_len);
    ghash_blocks(H, X, ct, ct_len);
    uint8_t lenblk[16];
    put_u64_be(lenblk, static_cast<uint64_t>(aad_len) * 8);
    put_u64_be(lenblk + 8, static_cast<uint64_t>(ct_len) * 8);
    for (int j = 0; j < 16; ++j) X[j] ^= lenblk[j];
    uint8_t tmp[16];
    gf_mul(X, H, tmp);                     // final GHASH block
    uint8_t ej0[16];
    aes256_encrypt_block(rk, J0, ej0);     // E_K(J0)
    for (int j = 0; j < 16; ++j) tag[j] = tmp[j] ^ ej0[j];
}

} // namespace

bool aes256_gcm_seal(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* pt, size_t pt_len,
                     uint8_t* ct_out, uint8_t tag_out[16]) {
    uint8_t rk[kAes256RoundKeyBytes];
    aes256_expand_key(key, rk);
    uint8_t zero[16] = {0}, H[16];
    aes256_encrypt_block(rk, zero, H);                 // H = E_K(0^128)

    uint8_t J0[16];
    std::memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;    // 96-bit IV -> J0 = IV||0^31||1

    uint8_t ctr[16];
    std::memcpy(ctr, J0, 16);
    inc32(ctr);                                        // first data counter
    gctr(rk, ctr, pt, pt_len, ct_out);

    compute_tag(rk, H, J0, aad, aad_len, ct_out, pt_len, tag_out);
    return true;
}

bool aes256_gcm_open(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len,
                     const uint8_t tag[16], uint8_t* pt_out) {
    uint8_t rk[kAes256RoundKeyBytes];
    aes256_expand_key(key, rk);
    uint8_t zero[16] = {0}, H[16];
    aes256_encrypt_block(rk, zero, H);

    uint8_t J0[16];
    std::memcpy(J0, nonce, 12);
    J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;

    uint8_t expected[16];
    compute_tag(rk, H, J0, aad, aad_len, ct, ct_len, expected);

    // Constant-time tag compare; release plaintext only on match.
    uint8_t diff = 0;
    for (int j = 0; j < 16; ++j) diff |= expected[j] ^ tag[j];
    if (diff != 0) return false;

    uint8_t ctr[16];
    std::memcpy(ctr, J0, 16);
    inc32(ctr);
    gctr(rk, ctr, ct, ct_len, pt_out);
    return true;
}

} // namespace dicore::crypto
