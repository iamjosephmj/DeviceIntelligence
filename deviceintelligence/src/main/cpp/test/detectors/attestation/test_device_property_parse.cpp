// Host unit test for device-property tag extraction in attest_der (pure, no JNI).
// Build/run command at the bottom. Mirrors test_seccomp_verdict.cpp's approach.
#include "dicore/detectors/attestation/der/attest_der.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

using B = std::vector<uint8_t>;
static B tlv(uint8_t tag, const B& body) {
    B o{tag, (uint8_t)body.size()};
    o.insert(o.end(), body.begin(), body.end());
    return o;
}
static B cat(std::initializer_list<B> xs) {
    B o;
    for (const auto& x : xs) o.insert(o.end(), x.begin(), x.end());
    return o;
}
static B asc(const std::string& s) { return B(s.begin(), s.end()); }
// constructed context-specific, high-tag-number EXPLICIT wrapper: [tagnum] { body }
static B ctx(int tagnum, const B& body) {
    B t;
    int v = tagnum;
    do { t.insert(t.begin(), (uint8_t)(v & 0x7F)); v >>= 7; } while (v);
    for (size_t i = 0; i + 1 < t.size(); ++i) t[i] |= 0x80;
    B hdr{0xBF};  // class context (0x80) | constructed (0x20) | high-tag (0x1F)
    hdr.insert(hdr.end(), t.begin(), t.end());
    hdr.push_back((uint8_t)body.size());
    hdr.insert(hdr.end(), body.begin(), body.end());
    return hdr;
}

int main() {
    using namespace dicore;
    // teeEnforced AuthorizationList with brand[710] and model[717].
    B tee = tlv(0x30, cat({
        ctx(710, tlv(0x04, asc("google"))),
        ctx(717, tlv(0x04, asc("Pixel 6 Pro"))),
    }));
    // Minimal KeyDescription SEQUENCE leading fields the parser walks in order.
    B kdseq = tlv(0x30, cat({
        tlv(0x02, {0x03}),         // attestationVersion
        tlv(0x0A, {0x01}),         // securityLevel = TrustedEnvironment
        tlv(0x02, {0x04}),         // keymasterVersion
        tlv(0x0A, {0x01}),         // keymasterSecurityLevel
        tlv(0x04, B(32, 0xAB)),    // attestationChallenge (32 bytes)
        tlv(0x04, {}),             // uniqueId (empty)
        tlv(0x30, {}),             // softwareEnforced (empty)
        tee,                       // teeEnforced
    }));

    KdInfo kd;
    parse_keydescription(kdseq.data(), kdseq.size(), &kd);

    assert(kd.dev.any_present == true);
    assert(std::strcmp(kd.dev.brand, "google") == 0);
    assert(std::strcmp(kd.dev.model, "Pixel 6 Pro") == 0);
    assert(kd.dev.device[0] == '\0');   // absent tag -> empty
    assert(kd.sl == 1);                 // unrelated fields still parse

    // Absent device-ID tags -> any_present false (fail-open friendly).
    B kdseq2 = tlv(0x30, cat({
        tlv(0x02, {0x03}), tlv(0x0A, {0x01}), tlv(0x02, {0x04}), tlv(0x0A, {0x01}),
        tlv(0x04, B(32, 0xAB)), tlv(0x04, {}), tlv(0x30, {}), tlv(0x30, {}),
    }));
    KdInfo kd2;
    parse_keydescription(kdseq2.data(), kdseq2.size(), &kd2);
    assert(kd2.dev.any_present == false);

    printf("all device-property parse tests passed\n");
    return 0;
}
// Build & run (host):
//   clang++ -std=c++17 -I deviceintelligence/src/main/cpp \
//     deviceintelligence/src/main/cpp/dicore/detectors/attestation/test_device_property_parse.cpp \
//     deviceintelligence/src/main/cpp/dicore/detectors/attestation/der/attest_der.cpp \
//     -o /tmp/test_devprop && /tmp/test_devprop
