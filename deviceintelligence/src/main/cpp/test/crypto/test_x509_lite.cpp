// Host unit tests for x509_lite — the security-critical, attacker-facing DER
// field parser. Two layers:
//   (A) KAT: parse a REAL 4-cert StrongBox chain and assert field byte-ranges
//       match an independent oracle (DER walk x-checked with openssl asn1parse).
//   (B) DEEP edge cases: synthetic certs exercising every parser branch, plus a
//       malformed-DER matrix (bad tags, bad lengths, truncation) — every one must
//       fail-open (ok=false) and never read out of bounds.
// Build via tools/qa/native-unit-tests.sh.
#include "dicore/crypto/x509_lite.h"
#include "dicore/crypto/sha256.h"
#include "dicore/detectors/attestation/der/attest_der.h"   // kd_from_extensions

#include "test_x509_lite_data.h"                        // kCert0Hex..kCert3Hex

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;

Bytes unhex(const char* h) {
    Bytes v; size_t n = std::strlen(h);
    auto nib=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; return -1; };
    for (size_t i=0;i+1<n;i+=2) v.push_back((uint8_t)((nib(h[i])<<4)|nib(h[i+1])));
    return v;
}
std::string sha_hex(const uint8_t* p, size_t n) {
    uint8_t d[32]; dicore::sha::sha256(p, n, d);
    static const char* x="0123456789abcdef"; std::string s;
    for (int i=0;i<32;i++){ s+=x[d[i]>>4]; s+=x[d[i]&0xf]; }
    return s;
}
// --- minimal DER builder ---
Bytes der_len(size_t n) {
    Bytes o;
    if (n < 0x80) { o.push_back((uint8_t)n); return o; }
    Bytes t; size_t x=n; while (x){ t.push_back((uint8_t)(x&0xff)); x>>=8; }
    o.push_back((uint8_t)(0x80 | t.size()));
    for (auto it=t.rbegin(); it!=t.rend(); ++it) o.push_back(*it);
    return o;
}
Bytes tlv(uint8_t tag, const Bytes& c) {
    Bytes o; o.push_back(tag); Bytes l=der_len(c.size());
    o.insert(o.end(), l.begin(), l.end()); o.insert(o.end(), c.begin(), c.end());
    return o;
}
Bytes cat(std::initializer_list<Bytes> ps){ Bytes o; for (auto& p: ps) o.insert(o.end(),p.begin(),p.end()); return o; }
Bytes SEQ(const Bytes& c){ return tlv(0x30,c); }

// Assemble a minimal but well-formed cert. include_version/include_exts toggle
// the optional [0] version and [3] extensions; uids inserts [1]/[2] unique IDs.
Bytes mk_cert(bool include_version, bool include_uids, bool include_exts,
              const Bytes& serial_content, const Bytes& issuer_dn, const Bytes& subject_dn,
              const Bytes& exts_seq_content = {}) {
    Bytes fields;
    if (include_version) { Bytes v = tlv(0xA0, tlv(0x02, {0x02})); fields.insert(fields.end(), v.begin(), v.end()); }
    Bytes serial = tlv(0x02, serial_content);
    Bytes sigalg = SEQ({0x06,0x03,0x2a,0x03,0x04});      // arbitrary AlgId
    Bytes issuer = SEQ(issuer_dn);
    Bytes validity = SEQ({});
    Bytes subject = SEQ(subject_dn);
    Bytes spki = SEQ({0x30,0x03,0x06,0x01,0x2a, 0x03,0x02,0x00,0x01});  // arbitrary SPKI content
    fields = cat({fields, serial, sigalg, issuer, validity, subject, spki});
    if (include_uids) { Bytes u1=tlv(0x81,{0xAA}), u2=tlv(0x82,{0xBB}); fields=cat({fields,u1,u2}); }
    if (include_exts) { Bytes e3 = tlv(0xA3, SEQ(exts_seq_content)); fields=cat({fields,e3}); }
    return SEQ(SEQ(fields));   // Certificate ::= SEQ( tbsCertificate, ... ) — parser reads tbs only
}
} // namespace

int main() {
    using namespace dicore::crypto;

    // ========================= (A) real-chain KAT =========================
    auto c0 = unhex(kCert0Hex);
    CertView v = x509_parse(c0.data(), c0.size());
    assert(v.ok);
    assert(v.serial_len == 1 && v.serial[0] == 0x01);
    assert(sha_hex(v.issuer,  v.issuer_len)  == "e464a3706885de0fd347dc55fb95104a98fc773ded4d718457e60cae87765bfc");
    assert(sha_hex(v.subject, v.subject_len) == "fc8f81ce8bcb8a5d61dd1c99a1eb5cf26809c44414b6c5907b1244f9be1413c0");
    assert(sha_hex(v.spki,    v.spki_len)    == "8a99428adecefa3d14e66c78e4d3c4682fc5d285274018287905c00edc7d0066");
    assert(v.exts_len == 404 && v.exts[0] == 0x30);
    assert(sha_hex(v.exts,    v.exts_len)    == "94923f9f9ef8cbeb29946d8f66fc232a5dff17b882ca725bc61f47a6a79dbc95");
    dicore::KdInfo kd; dicore::kd_from_extensions(v.exts, v.exts_len, &kd);
    assert(kd.sl == 2 && kd.bs >= 0 && kd.bs <= 3);

    // multi-byte serial with a leading 0x00 (cert3), preserved verbatim.
    auto c3 = unhex(kCert3Hex);
    CertView v3 = x509_parse(c3.data(), c3.size());
    assert(v3.ok && v3.serial_len == 9 && v3.serial[0] == 0x00);

    // chain links by DN across all four real certs.
    Bytes cc[4] = {unhex(kCert0Hex), unhex(kCert1Hex), unhex(kCert2Hex), unhex(kCert3Hex)};
    CertView vv[4]; for (int i=0;i<4;i++){ vv[i]=x509_parse(cc[i].data(),cc[i].size()); assert(vv[i].ok); }
    for (int i=0;i<3;i++) assert(vv[i].issuer_len==vv[i+1].subject_len &&
        std::memcmp(vv[i].issuer, vv[i+1].subject, vv[i].issuer_len)==0);

    // ========================= (B) deep edge cases =========================
    // v1 cert (no [0] version): serial read directly; no extensions.
    {
        Bytes issuer={0x11,0x22}, subject={0x33,0x44};
        Bytes c = mk_cert(/*ver*/false, /*uids*/false, /*exts*/false, {0x2a}, issuer, subject);
        CertView x = x509_parse(c.data(), c.size());
        assert(x.ok);
        assert(x.serial_len==1 && x.serial[0]==0x2a);
        assert(x.issuer_len==SEQ(issuer).size() && std::memcmp(x.issuer, SEQ(issuer).data(), x.issuer_len)==0);
        assert(x.subject_len==SEQ(subject).size());
        assert(x.exts == nullptr && x.exts_len == 0);        // no [3]
    }
    // v3 cert with [0] version present: version skipped, serial found.
    {
        Bytes c = mk_cert(true, false, false, {0x07}, {0x01}, {0x02});
        CertView x = x509_parse(c.data(), c.size());
        assert(x.ok && x.serial_len==1 && x.serial[0]==0x07);
    }
    // [1]/[2] unique IDs before [3]: extensions still located (skipped correctly).
    {
        Bytes extsInner = {0x30,0x03,0x06,0x01,0x2a};        // one inner Extension SEQ
        Bytes c = mk_cert(true, /*uids*/true, /*exts*/true, {0x01}, {0x0a}, {0x0b}, extsInner);
        CertView x = x509_parse(c.data(), c.size());
        assert(x.ok && x.exts != nullptr && x.exts[0]==0x30);
        assert(x.exts_len == SEQ(extsInner).size());
    }
    // [3] wrapping a NON-SEQUENCE inner: exts left null, but parse still ok.
    {
        Bytes fields;
        Bytes serial=tlv(0x02,{0x01}), sigalg=SEQ({}), issuer=SEQ({0x01}), val=SEQ({}), subj=SEQ({0x02}), spki=SEQ({0x05,0x00});
        Bytes bad3 = tlv(0xA3, Bytes{0x02,0x01,0x09});       // [3] wrapping an INTEGER (not SEQ)
        fields = cat({serial,sigalg,issuer,val,subj,spki,bad3});
        Bytes c = SEQ(SEQ(fields));
        CertView x = x509_parse(c.data(), c.size());
        assert(x.ok && x.exts == nullptr && x.exts_len == 0);
    }

    // ---- malformed matrix: every case must be ok==false and never OOB ----
    auto rejects = [](const Bytes& b){ return !x509_parse(b.data(), b.size()).ok; };
    // outer not a SEQUENCE
    { Bytes c = mk_cert(false,false,false,{0x01},{0x01},{0x02}); c[0]=0x31; assert(rejects(c)); }
    // issuer not a SEQUENCE (tbs field-3 tag wrong): hand-build with issuer tag 0x31
    {
        Bytes serial=tlv(0x02,{0x01}), sigalg=SEQ({}), issuer=tlv(0x31,{0x01}), val=SEQ({}), subj=SEQ({0x02}), spki=SEQ({0x05,0x00});
        Bytes c = SEQ(SEQ(cat({serial,sigalg,issuer,val,subj,spki})));
        assert(rejects(c));
    }
    // missing SPKI (tbs ends after subject)
    {
        Bytes serial=tlv(0x02,{0x01}), sigalg=SEQ({}), issuer=SEQ({0x01}), val=SEQ({}), subj=SEQ({0x02});
        Bytes c = SEQ(SEQ(cat({serial,sigalg,issuer,val,subj})));
        assert(rejects(c));
    }
    // indefinite length (0x80) anywhere
    { Bytes c = {0x30,0x80,0x02,0x01,0x01}; assert(rejects(c)); }
    // length field claims >4 length-of-length bytes
    { Bytes c = {0x30,0x85,0,0,0,0,0}; assert(rejects(c)); }
    // content length overruns the buffer
    { Bytes c = {0x30,0x0a,0x02,0x01}; assert(rejects(c)); }   // says 10 bytes, has 2
    // long-form length that is itself truncated
    { Bytes c = {0x30,0x82,0x00}; assert(rejects(c)); }
    // tiny/empty inputs
    { Bytes c={}; assert(rejects(c)); }
    { Bytes c={0x30}; assert(rejects(c)); }
    { Bytes c={0x30,0x00}; assert(rejects(c)); }               // empty SEQUENCE -> no tbs
    // truncation sweep over the real leaf: every proper prefix must fail-open, no crash
    for (size_t k = 0; k < c0.size(); ++k) {
        CertView x = x509_parse(c0.data(), k);
        assert(!x.ok);                                          // a prefix is never a full cert
    }
    // every returned view of the real leaf lies within the buffer (no escape)
    {
        const uint8_t* end = c0.data()+c0.size();
        auto in=[&](const uint8_t* p,size_t n){ return p==nullptr || (p>=c0.data() && p+n<=end); };
        assert(in(v.serial,v.serial_len)&&in(v.issuer,v.issuer_len)&&in(v.subject,v.subject_len)&&in(v.spki,v.spki_len)&&in(v.exts,v.exts_len));
    }

    std::printf("test_x509_lite OK (deep edge matrix)\n");
    return 0;
}
