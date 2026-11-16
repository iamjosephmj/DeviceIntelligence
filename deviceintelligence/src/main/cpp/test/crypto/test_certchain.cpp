// Host unit tests for the self-owned certchain (structural verify). Covers every
// verify() branch (subject-DN anchor, issuer-DN anchor, byte-identical anchor,
// broken link, no anchor, reversed order, unparseable cert, empty) on the real
// StrongBox chain + the pinned Google roots. Build via native-unit-tests.sh.
#include "dicore/crypto/certchain.h"
#include "dicore/detectors/attestation/policy/attest_roots.h"   // kGoogleAttestRoots

#include "test_x509_lite_data.h"                          // kCert0Hex..kCert3Hex

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;
Bytes unhex(const char* h){ Bytes v; size_t n=std::strlen(h);
    auto nb=[](char c)->int{ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; return -1; };
    for(size_t i=0;i+1<n;i+=2) v.push_back((uint8_t)((nb(h[i])<<4)|nb(h[i+1]))); return v; }
void add_roots(dicore::crypto::CertChain& t){ for(int i=0;i<kGoogleAttestRootCount;++i) t.add_der(kGoogleAttestRoots[i].der,kGoogleAttestRoots[i].len); }
bool trusted(std::initializer_list<Bytes> chain, bool with_roots){
    dicore::crypto::CertChain c, t;
    for (auto& d : chain) c.add_der(d.data(), d.size());
    if (with_roots) add_roots(t);
    uint32_t f=0; return c.verify(t,&f)==0;
}
// minimal no-extensions cert (for the leaf_extensions negative case)
Bytes tlv(uint8_t tag, const Bytes& c){ Bytes o; o.push_back(tag);
    if(c.size()<0x80) o.push_back((uint8_t)c.size());
    else { Bytes t; size_t x=c.size(); while(x){t.push_back(x&0xff);x>>=8;} o.push_back(0x80|t.size()); for(auto it=t.rbegin();it!=t.rend();++it)o.push_back(*it);} 
    o.insert(o.end(),c.begin(),c.end()); return o; }
Bytes SEQ(const Bytes& c){ return tlv(0x30,c); }
Bytes cat(std::initializer_list<Bytes> ps){ Bytes o; for(auto&p:ps)o.insert(o.end(),p.begin(),p.end()); return o; }
Bytes mk_noexts(){ Bytes s=tlv(0x02,{0x01}),sa=SEQ({}),is=SEQ({0x0a}),va=SEQ({}),su=SEQ({0x0b}),pk=SEQ({0x05,0x00});
    return SEQ(SEQ(cat({s,sa,is,va,su,pk}))); }
} // namespace

int main() {
    using namespace dicore::crypto;
    Bytes c0=unhex(kCert0Hex), c1=unhex(kCert1Hex), c2=unhex(kCert2Hex), c3=unhex(kCert3Hex);
    Bytes root0(kGoogleAttestRoots[0].der, kGoogleAttestRoots[0].der+kGoogleAttestRoots[0].len);
    Bytes junk = {0xAB,0xCD,0xEF};

    // --- positive verify() branches ---
    assert(trusted({c0,c1,c2,c3}, true));       // subject-DN anchor: top(cert3).subject == root0.subject
    assert(trusted({c0,c1,c2},    true));       // issuer-DN anchor: cert2.issuer == root0.subject (root absent from chain)
    assert(trusted({root0},       true));       // byte-identical anchor: top IS a pinned root

    // --- negative verify() branches ---
    assert(!trusted({c0,c1,c2,c3}, false));     // no trust roots -> no anchor
    assert(!trusted({c0,c2,c3},    true));      // broken link: cert0.issuer != cert2.subject
    assert(!trusted({c3,c2,c1,c0}, true));      // reversed order -> links fail
    assert(!trusted({c0},          true));      // leaf alone: its DN matches no root
    assert(!trusted({},            true));      // empty chain -> error

    // --- add_der contract + unparseable cert aborts verify ---
    {
        CertChain c, t; add_roots(t);
        assert(c.add_der(c0.data(), c0.size()) == 0);     // real cert parses
        assert(c.add_der(junk.data(), junk.size()) != 0); // junk -> nonzero
        c.add_der(c2.data(), c2.size());
        uint32_t f=0; assert(c.verify(t,&f) != 0);        // any unparsed cert -> not trusted
    }

    // --- serials(): leaf-first, multi-byte with leading zero preserved ---
    {
        CertChain c; for (auto* d : {&c0,&c1,&c2,&c3}) c.add_der(d->data(), d->size());
        auto ser = c.serials();
        assert(ser.size()==4);
        assert(ser[0].size()==1 && ser[0][0]==0x01);              // leaf serial
        assert(ser[3].size()==9 && ser[3][0]==0x00);              // root serial, 9 bytes, leading 00
    }

    // --- leaf_extensions: present on real leaf, absent on a no-exts cert ---
    {
        CertChain c; c.add_der(c0.data(), c0.size());
        const uint8_t* p=nullptr; size_t n=0;
        assert(c.leaf_extensions(&p,&n) && n>0 && p[0]==0x30);
    }
    {
        Bytes ne = mk_noexts();
        CertChain c; assert(c.add_der(ne.data(), ne.size())==0);
        const uint8_t* p=(const uint8_t*)1; size_t n=99;
        assert(!c.leaf_extensions(&p,&n));                        // no v3 exts -> false
    }

    // --- spki_of_der: real leaf (P-256 SPKI == 91B), junk -> empty ---
    { auto s = spki_of_der(c0.data(), c0.size()); assert(s.size()==91 && s[0]==0x30); }
    { auto s = spki_of_der(junk.data(), junk.size()); assert(s.empty()); }

    std::printf("test_certchain OK\n");
    return 0;
}
