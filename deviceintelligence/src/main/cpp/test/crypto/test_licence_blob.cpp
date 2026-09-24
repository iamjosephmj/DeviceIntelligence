// Host unit test for the licence parser. Builds a valid 72-byte blob (matching
// tools/keys/gen-licence-key.sh) with a real SHA-256 checksum, then checks the
// reject paths. Build/run at the bottom.
#include "dicore/crypto/licence_blob.h"
#include "dicore/crypto/sha256.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    using namespace dicore::crypto;

    // Assemble a valid body: magic, ver, epoch=7, curve=1, rsvd=0, pubkey(32).
    std::vector<uint8_t> blob(72, 0);
    std::memcpy(blob.data(), "RVN1", 4);
    blob[4] = 0x01;
    blob[5] = 0x07;                       // epoch
    blob[6] = 0x01;                       // curve X25519
    blob[7] = 0x00;
    for (int i = 0; i < 32; ++i) blob[8 + i] = static_cast<uint8_t>(0xA0 + i);  // pubkey
    uint8_t sum[32];
    assert(dicore::sha::sha256(blob.data(), 40, sum));
    std::memcpy(blob.data() + 40, sum, 32);

    LicenceKey k;
    assert(licence_blob_parse(blob.data(), blob.size(), &k));
    assert(k.epoch == 7);
    for (int i = 0; i < 32; ++i) assert(k.pubkey[i] == static_cast<uint8_t>(0xA0 + i));

    // Reject: wrong length.
    assert(!licence_blob_parse(blob.data(), 71, &k));
    // Reject: bad magic.
    { auto b = blob; b[0] = 'X'; assert(!licence_blob_parse(b.data(), b.size(), &k)); }
    // Reject: wrong version.
    { auto b = blob; b[4] = 0x02; assert(!licence_blob_parse(b.data(), b.size(), &k)); }
    // Reject: wrong curve.
    { auto b = blob; b[6] = 0x02; assert(!licence_blob_parse(b.data(), b.size(), &k)); }
    // Reject: corrupted checksum.
    { auto b = blob; b[71] ^= 0x01; assert(!licence_blob_parse(b.data(), b.size(), &k)); }
    // Reject: corrupted body (checksum no longer matches).
    { auto b = blob; b[8] ^= 0x01; assert(!licence_blob_parse(b.data(), b.size(), &k)); }

    // --- RVN2: signed, package-bound, expiring -------------------------------
    // Body layout: magic(4) ver(1)=2 epoch(1) curve(1)=1 flags(1) pubkey(32)
    //              pkgHash(32) notAfter(8, big-endian) | sig(64)
    std::vector<uint8_t> b2(144, 0);
    std::memcpy(b2.data(), "RVN2", 4);
    b2[4] = 0x02;
    b2[5] = 0x09;                          // epoch
    b2[6] = 0x01;                          // curve = X25519
    b2[7] = 0x00;                          // flags
    for (int i = 0; i < 32; ++i) b2[8 + i]  = static_cast<uint8_t>(0xB0 + i);   // pubkey
    for (int i = 0; i < 32; ++i) b2[40 + i] = static_cast<uint8_t>(0xC0 + i);   // pkgHash
    b2[79] = 0x2A;                         // notAfter = 42
    licence_blob_sign_for_test(b2.data(), b2.data() + 80);

    LicenceKey k2;
    assert(licence_blob_parse(b2.data(), b2.size(), &k2));
    assert(k2.epoch == 9);
    assert(k2.not_after == 42);
    assert(k2.pkg_hash[0] == 0xC0 && k2.pkg_hash[31] == 0xDF);
    assert(k2.pubkey[0] == 0xB0 && k2.pubkey[31] == 0xCF);

    // RVN1 must still parse, and must report no package binding and no expiry so the
    // caller can tell "unbound blob" from "bound to the empty string".
    assert(licence_blob_parse(blob.data(), blob.size(), &k));
    assert(k.not_after == 0);
    for (int i = 0; i < 32; ++i) assert(k.pkg_hash[i] == 0);

    // Reject: a flipped package byte breaks the signature.
    { auto b = b2; b[40] ^= 0xFF; assert(!licence_blob_parse(b.data(), b.size(), &k2)); }
    // Reject: a flipped pubkey byte breaks the signature.
    { auto b = b2; b[8] ^= 0x01;  assert(!licence_blob_parse(b.data(), b.size(), &k2)); }
    // Reject: a corrupted signature.
    { auto b = b2; b[80] ^= 0x01; assert(!licence_blob_parse(b.data(), b.size(), &k2)); }
    // Reject: a non-zero reserved tail — a future scheme widens into it, so an old
    // reader must refuse rather than ignore what it cannot understand.
    { auto b = b2; b[112] = 0x01; assert(!licence_blob_parse(b.data(), b.size(), &k2)); }
    // Reject: wrong length, wrong magic, wrong version, wrong curve.
    { assert(!licence_blob_parse(b2.data(), 143, &k2)); }
    { auto b = b2; b[3] = 'X';    assert(!licence_blob_parse(b.data(), b.size(), &k2)); }
    { auto b = b2; b[4] = 0x03;   assert(!licence_blob_parse(b.data(), b.size(), &k2)); }
    { auto b = b2; b[6] = 0x02;   assert(!licence_blob_parse(b.data(), b.size(), &k2)); }

    std::printf("test_licence_blob: RVN1 + RVN2 OK\n");
    return 0;
}


/* Build/run (host; needs an android/log.h shim for sha256.cpp):
     CPP=deviceintelligence/src/main/cpp
     c++ -std=c++17 -I"$CPP" -I<hostshim> "$CPP/test/crypto/test_licence_blob.cpp" \
         "$CPP/dicore/crypto/licence_blob.cpp" "$CPP/dicore/crypto/sha256.cpp" \
         "$CPP/dicore/crypto/hkdf.cpp" \
         -o /tmp/test_licence_blob && /tmp/test_licence_blob */
