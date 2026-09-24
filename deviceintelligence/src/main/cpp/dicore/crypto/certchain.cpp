#include "dicore/crypto/certchain.h"

#include "dicore/crypto/x509_lite.h"

#include <cstring>
#include <vector>

// Self-owned certchain: PARSING via x509_lite; on-device verify() is a STRUCTURAL
// DN-chaining check to the pinned roots (NO signatures). Cryptographic chain
// verification is the backend's authority (ChainVerifier re-verifies every
// signature to a pinned Google root on the device-forwarded chain), so on-device
// signature verification is redundant for trust — this is the "signed sensor"
// contract (see docs/specs/2026-08-22-mbedtls-retirement-design.md §3). Retires the vendored X.509 engine entirely.
namespace dicore::crypto {
namespace {

struct Chain {
    std::vector<std::vector<uint8_t>> der;   // owned DER copies (moved buffers keep
                                             // their heap storage across reallocs)
    std::vector<CertView> view;              // views into der[i]
};
inline Chain* as_chain(void* p) { return static_cast<Chain*>(p); }

inline bool distinguished_name_eq(const uint8_t* a, size_t an, const uint8_t* b, size_t bn) {
    return a != nullptr && b != nullptr && an == bn && an > 0 && std::memcmp(a, b, an) == 0;
}

}  // namespace

CertChain::CertChain() { impl_ = new Chain(); }
CertChain::~CertChain() { delete as_chain(impl_); }

int CertChain::add_der(const uint8_t* der, size_t len) {
    Chain* c = as_chain(impl_);
    c->der.emplace_back(der, der + len);
    CertView v = x509_parse(c->der.back().data(), c->der.back().size());
    c->view.push_back(v);
    return v.ok ? 0 : -1;
}

std::vector<std::vector<uint8_t>> CertChain::serials() const {
    std::vector<std::vector<uint8_t>> out;
    for (const auto& v : as_chain(impl_)->view)
        if (v.ok && v.serial != nullptr) out.emplace_back(v.serial, v.serial + v.serial_len);
    return out;
}

bool CertChain::leaf_extensions(const uint8_t** p, size_t* len) const {
    Chain* c = as_chain(impl_);
    if (c->view.empty()) { *p = nullptr; *len = 0; return false; }
    const CertView& leaf = c->view.front();
    *p = leaf.exts; *len = leaf.exts_len;
    return leaf.exts != nullptr;
}

// Structural verification: (1) every cert links to the next by DN
// (issuer[i] == subject[i+1]); (2) the top cert ties to a pinned trust root — by
// subject-DN (self-signed root, or a re-issued root sharing the pinned identity),
// by issuer-DN (root not carried in the chain), or by exact bytes. Returns 0 iff
// both hold. Signatures are the backend's job.
int CertChain::verify(CertChain& trust, uint32_t* flags) {
    if (flags) *flags = 0;
    Chain* c = as_chain(impl_);
    Chain* t = as_chain(trust.impl_);

    if (c->view.empty()) { if (flags) *flags = 0xFFFFFFFFu; return -1; }
    for (const auto& v : c->view)
        if (!v.ok) { if (flags) *flags = 0xFFFFFFFFu; return -1; }

    for (size_t i = 0; i + 1 < c->view.size(); ++i) {
        if (!distinguished_name_eq(c->view[i].issuer, c->view[i].issuer_len,
                   c->view[i + 1].subject, c->view[i + 1].subject_len)) {
            if (flags) *flags = 0x8u;   // chain-not-trusted flag
            return -1;
        }
    }

    const CertView& top = c->view.back();
    for (const auto& r : t->view) {
        if (!r.ok) continue;
        if (distinguished_name_eq(top.subject, top.subject_len, r.subject, r.subject_len)) return 0;
        if (distinguished_name_eq(top.issuer, top.issuer_len, r.subject, r.subject_len)) return 0;
    }
    for (const auto& rd : t->der)
        for (const auto& cd : c->der)
            if (!rd.empty() && rd.size() == cd.size() &&
                std::memcmp(rd.data(), cd.data(), rd.size()) == 0)
                return 0;

    if (flags) *flags = 0x8u;
    return -1;
}

std::vector<uint8_t> spki_of_der(const uint8_t* der, size_t len) {
    CertView v = x509_parse(der, len);
    std::vector<uint8_t> out;
    if (v.ok && v.spki != nullptr && v.spki_len > 0) out.assign(v.spki, v.spki + v.spki_len);
    return out;
}

}  // namespace dicore::crypto
