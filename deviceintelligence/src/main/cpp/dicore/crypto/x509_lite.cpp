#include "dicore/crypto/x509_lite.h"

namespace dicore::crypto {
namespace {

struct Tlv {
    uint8_t tag = 0;
    const uint8_t* content = nullptr;  size_t content_len = 0;
    const uint8_t* elem = nullptr;     size_t elem_len = 0;  // whole element incl tag+len
};

// Read one DER TLV at absolute offset *pos within [buf, buf+end). Advances *pos
// past the whole element. Rejects truncation, indefinite length, >4-byte length
// fields, and any content that overruns [.,end). end is an absolute bound so the
// same primitive constrains reads to a parent element's content.
bool read_tlv(const uint8_t* buf, size_t end, size_t* pos, Tlv* out) {
    size_t i = *pos;
    if (i >= end) return false;
    const uint8_t* elem = buf + i;
    uint8_t tag = buf[i++];
    if (i >= end) return false;
    size_t l = buf[i++];
    if (l & 0x80) {
        size_t n = l & 0x7f;
        if (n == 0 || n > 4) return false;          // indefinite or absurd length
        if (i + n > end) return false;
        l = 0;
        for (size_t k = 0; k < n; ++k) l = (l << 8) | buf[i++];
    }
    if (l > end - i) return false;                  // content overruns the bound
    out->tag = tag;
    out->content = buf + i; out->content_len = l;
    out->elem = elem;       out->elem_len = static_cast<size_t>((buf + i + l) - elem);
    *pos = i + l;
    return true;
}

}  // namespace

CertView x509_parse(const uint8_t* der, size_t len) {
    CertView v;
    if (der == nullptr || len < 4) return v;

    size_t p = 0;
    Tlv cert;
    if (!read_tlv(der, len, &p, &cert) || cert.tag != 0x30) return v;   // Certificate

    size_t tp = static_cast<size_t>(cert.content - der);
    size_t tend = tp + cert.content_len;
    Tlv tbs;
    if (!read_tlv(der, tend, &tp, &tbs) || tbs.tag != 0x30) return v;   // tbsCertificate

    size_t q = static_cast<size_t>(tbs.content - der);
    size_t qend = q + tbs.content_len;
    Tlv t;

    if (!read_tlv(der, qend, &q, &t)) return v;
    if (t.tag == 0xA0) {                                                // optional version [0]
        if (!read_tlv(der, qend, &q, &t)) return v;
    }
    if (t.tag != 0x02) return v;                                        // serialNumber
    v.serial = t.content; v.serial_len = t.content_len;

    if (!read_tlv(der, qend, &q, &t) || t.tag != 0x30) return v;        // signature AlgId
    if (!read_tlv(der, qend, &q, &t) || t.tag != 0x30) return v;        // issuer
    v.issuer = t.elem; v.issuer_len = t.elem_len;
    if (!read_tlv(der, qend, &q, &t) || t.tag != 0x30) return v;        // validity
    if (!read_tlv(der, qend, &q, &t) || t.tag != 0x30) return v;        // subject
    v.subject = t.elem; v.subject_len = t.elem_len;
    if (!read_tlv(der, qend, &q, &t) || t.tag != 0x30) return v;        // SubjectPublicKeyInfo
    v.spki = t.elem; v.spki_len = t.elem_len;

    // Optional issuerUniqueID [1], subjectUniqueID [2], then extensions [3].
    while (q < qend) {
        if (!read_tlv(der, qend, &q, &t)) break;
        if (t.tag == 0xA3) {                                            // [3] EXPLICIT
            size_t xp = static_cast<size_t>(t.content - der);
            size_t xend = xp + t.content_len;
            Tlv x;
            if (read_tlv(der, xend, &xp, &x) && x.tag == 0x30) {        // inner Extensions SEQ
                v.exts = x.elem; v.exts_len = x.elem_len;
            }
            break;
        }
    }

    v.ok = true;
    return v;
}

}  // namespace dicore::crypto
