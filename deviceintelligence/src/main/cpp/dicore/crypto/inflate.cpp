#include "dicore/crypto/inflate.h"

// Self-owned raw-DEFLATE (RFC 1951) inflater — replaces the vendored miniz.
// Runs on attacker-influenced compressed APK bytes (App Bundle bundle-mode
// integrity), so it is fully bounds-checked, fail-closed (nullptr on any
// malformation), and hard-capped against decompression bombs. Same facade
// contract as before: returns a malloc'd buffer (free() it); *out_len set.
// Canonical Huffman decode after RFC 1951 §3.2.

#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace dicore::crypto {
namespace {

constexpr size_t kMaxOut = 256u * 1024 * 1024;   // decompression-bomb guard
constexpr int kMaxBits = 15;

// RFC 1951 §3.2.5 length/distance base + extra-bit tables.
const uint16_t kLenBase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
const uint8_t  kLenExtra[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
const uint16_t kDistBase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
const uint8_t  kDistExtra[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
// Code-length code order (RFC 1951 §3.2.7).
const uint8_t kCLOrder[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};

struct BitReader {
    const uint8_t* in; size_t len; size_t pos = 0;
    uint32_t buf = 0; int cnt = 0; bool err = false;
    int bit() {
        if (cnt == 0) {
            if (pos >= len) { err = true; return 0; }
            buf = in[pos++]; cnt = 8;
        }
        int b = buf & 1; buf >>= 1; --cnt; return b;
    }
    uint32_t bits(int n) {                 // n LSB-first bits
        uint32_t v = 0;
        for (int i = 0; i < n; ++i) v |= (uint32_t)bit() << i;
        return v;
    }
    void align() { cnt = 0; buf = 0; }     // drop to next byte boundary
};

struct Huff {
    int16_t counts[kMaxBits + 1];
    int16_t* symbols;                      // caller-provided storage, size >= n
};

// Canonical Huffman decode (RFC 1951): read bits MSB-into-code until a code
// resolves. Returns the symbol, or -1 on error / bad code / input exhaustion.
int decode(BitReader& br, const Huff& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= kMaxBits; ++len) {
        code |= br.bit();
        if (br.err) return -1;
        int count = h.counts[len];
        if (code - count < first) return h.symbols[index + (code - first)];
        index += count; first += count; first <<= 1; code <<= 1;
    }
    return -1;
}

// Build a Huffman table from code lengths. Returns false if over-subscribed.
bool build(Huff& h, const uint8_t* lengths, int n, int16_t* sym_store) {
    for (int i = 0; i <= kMaxBits; ++i) h.counts[i] = 0;
    for (int i = 0; i < n; ++i) {
        if (lengths[i] > kMaxBits) return false;
        h.counts[lengths[i]]++;
    }
    h.counts[0] = 0;
    int left = 1;
    for (int len = 1; len <= kMaxBits; ++len) { left <<= 1; left -= h.counts[len]; if (left < 0) return false; }
    int offs[kMaxBits + 2]; offs[1] = 0;
    for (int len = 1; len <= kMaxBits; ++len) offs[len + 1] = offs[len] + h.counts[len];
    h.symbols = sym_store;
    for (int i = 0; i < n; ++i) if (lengths[i]) h.symbols[offs[lengths[i]]++] = (int16_t)i;
    return true;
}

struct Out {
    uint8_t* p = nullptr; size_t len = 0; size_t cap = 0; bool err = false;
    bool grow(size_t need) {
        if (need <= cap) return true;
        if (need > kMaxOut) { err = true; return false; }
        size_t nc = cap ? cap : 1024;
        while (nc < need) { nc <<= 1; if (nc > kMaxOut) nc = kMaxOut; if (nc < need && nc == kMaxOut) { err = true; return false; } }
        uint8_t* np = (uint8_t*)realloc(p, nc);
        if (!np) { err = true; return false; }
        p = np; cap = nc; return true;
    }
    bool put(uint8_t b) { if (!grow(len + 1)) return false; p[len++] = b; return true; }
};

// Decode one Huffman-coded block body (fixed or dynamic) into out.
bool inflate_block(BitReader& br, Out& out, const Huff& lit, const Huff& dist) {
    for (;;) {
        int sym = decode(br, lit);
        if (sym < 0) return false;
        if (sym == 256) return true;                  // end of block
        if (sym < 256) { if (!out.put((uint8_t)sym)) return false; continue; }
        sym -= 257;
        if (sym >= 29) return false;                  // 286/287 are invalid
        size_t length = kLenBase[sym] + br.bits(kLenExtra[sym]);
        int dsym = decode(br, dist);
        if (dsym < 0 || dsym >= 30) return false;
        size_t d = kDistBase[dsym] + br.bits(kDistExtra[dsym]);
        if (br.err) return false;
        if (d == 0 || d > out.len) return false;      // back-ref before start
        for (size_t k = 0; k < length; ++k) {
            uint8_t b = out.p[out.len - d];            // read BEFORE put (put may realloc)
            if (!out.put(b)) return false;
        }
    }
}

bool inflate_fixed(BitReader& br, Out& out) {
    uint8_t litlen[288]; int16_t litsym[288];
    for (int i = 0; i < 144; ++i) litlen[i] = 8;
    for (int i = 144; i < 256; ++i) litlen[i] = 9;
    for (int i = 256; i < 280; ++i) litlen[i] = 7;
    for (int i = 280; i < 288; ++i) litlen[i] = 8;
    uint8_t distlen[30]; int16_t distsym[30];
    for (int i = 0; i < 30; ++i) distlen[i] = 5;
    Huff lit{}, dist{};
    if (!build(lit, litlen, 288, litsym)) return false;
    if (!build(dist, distlen, 30, distsym)) return false;
    return inflate_block(br, out, lit, dist);
}

bool inflate_dynamic(BitReader& br, Out& out) {
    int hlit = br.bits(5) + 257;
    int hdist = br.bits(5) + 1;
    int hclen = br.bits(4) + 4;
    if (br.err || hlit > 286 || hdist > 30) return false;

    uint8_t cl_len[19] = {0};
    for (int i = 0; i < hclen; ++i) cl_len[kCLOrder[i]] = (uint8_t)br.bits(3);
    if (br.err) return false;
    Huff clh{}; int16_t clsym[19];
    if (!build(clh, cl_len, 19, clsym)) return false;

    // Decode hlit+hdist code lengths (with repeat codes 16/17/18).
    uint8_t lens[286 + 30] = {0};
    int total = hlit + hdist, i = 0;
    while (i < total) {
        int s = decode(br, clh);
        if (s < 0) return false;
        if (s < 16) { lens[i++] = (uint8_t)s; }
        else if (s == 16) {
            if (i == 0) return false;
            int rep = 3 + br.bits(2); uint8_t prev = lens[i - 1];
            while (rep-- && i < total) lens[i++] = prev;
        } else if (s == 17) {
            int rep = 3 + br.bits(3); while (rep-- && i < total) lens[i++] = 0;
        } else { // 18
            int rep = 11 + br.bits(7); while (rep-- && i < total) lens[i++] = 0;
        }
        if (br.err) return false;
    }
    Huff lit{}, dist{}; int16_t litsym[286], distsym[30];
    if (!build(lit, lens, hlit, litsym)) return false;
    if (!build(dist, lens + hlit, hdist, distsym)) return false;
    return inflate_block(br, out, lit, dist);
}

bool inflate_stored(BitReader& br, Out& out) {
    br.align();
    if (br.pos + 4 > br.len) return false;
    uint16_t len  = (uint16_t)(br.in[br.pos] | (br.in[br.pos + 1] << 8));
    uint16_t nlen = (uint16_t)(br.in[br.pos + 2] | (br.in[br.pos + 3] << 8));
    br.pos += 4;
    if ((uint16_t)~len != nlen) return false;
    if (br.pos + len > br.len) return false;
    if (!out.grow(out.len + len)) return false;
    memcpy(out.p + out.len, br.in + br.pos, len);
    out.len += len; br.pos += len;
    return true;
}

}  // namespace

void* inflate_deflate(const void* in, size_t in_len, size_t* out_len) {
    if (out_len) *out_len = 0;
    if (in == nullptr) return nullptr;
    BitReader br{static_cast<const uint8_t*>(in), in_len};
    Out out;
    bool ok = true, final_block = false;
    while (!final_block) {
        final_block = br.bit() != 0;
        if (br.err) { ok = false; break; }
        int btype = (int)br.bits(2);
        if (br.err) { ok = false; break; }
        if (btype == 0) ok = inflate_stored(br, out);
        else if (btype == 1) ok = inflate_fixed(br, out);
        else if (btype == 2) ok = inflate_dynamic(br, out);
        else ok = false;                              // btype 3 reserved
        if (!ok || out.err) { ok = false; break; }
    }
    if (!ok) { free(out.p); return nullptr; }
    if (out.p == nullptr) out.p = (uint8_t*)malloc(1);  // valid non-null for 0-length output
    if (out.p == nullptr) return nullptr;
    if (out_len) *out_len = out.len;
    return out.p;
}

}  // namespace dicore::crypto
