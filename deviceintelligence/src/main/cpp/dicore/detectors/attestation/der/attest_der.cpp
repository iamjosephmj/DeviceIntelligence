#include "dicore/detectors/attestation/der/attest_der.h"
#include "dicore/platform/obf.h"  // DI_OBF_ATTEST — heaviest passes on the parser path

#include <cstring>

// Pure DER walker for the KeyDescription extension (see attest_der.h). No
// external dependencies so it links into a libFuzzer harness as-is (spec §4.4).

namespace dicore {
namespace {

// Universal ASN.1 tag numbers (mirror KeyDescriptionParser).
constexpr int kTagBoolean = 1;
constexpr int kTagInteger = 2;
constexpr int kTagOctetString = 4;
constexpr int kTagOid = 6;
constexpr int kTagEnumerated = 10;
constexpr int kTagSequence = 16;

constexpr int kClassUniversal = 0;
constexpr int kClassContext = 2;

constexpr int kTagRootOfTrust = 704;
constexpr int kTagAttIdBrand = 710;
constexpr int kTagAttIdDevice = 711;
constexpr int kTagAttIdProduct = 712;
constexpr int kTagAttIdManufacturer = 716;
constexpr int kTagAttIdModel = 717;

// DER content of OID 1.3.6.1.4.1.11129.2.1.17 (the KeyDescription extension).
constexpr unsigned char kKeyDescOid[] = {
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11};

struct Slice {
    const uint8_t* p;
    size_t n;
};

// Bounds-checked DER reader — direct port of KeyDescriptionParser.Reader.
class Reader {
public:
    Reader(const uint8_t* buf, size_t len) : buf_(buf), len_(len), pos_(0) {}
    size_t remaining() const { return len_ - pos_; }

    bool read_universal(int expected, Slice* out) {
        size_t saved = pos_;
        Header h;
        if (!read_header(&h)) { pos_ = saved; return false; }
        if (h.tag_class != kClassUniversal || h.tag_num != expected) { pos_ = saved; return false; }
        out->p = buf_ + pos_;
        out->n = h.length;
        pos_ += h.length;
        return true;
    }

    bool read_any(int* tag_class, int* tag_num, Slice* out) {
        Header h;
        if (!read_header(&h)) return false;
        *tag_class = h.tag_class;
        *tag_num = h.tag_num;
        out->p = buf_ + pos_;
        out->n = h.length;
        pos_ += h.length;
        return true;
    }

    bool read_enum(int* value) {
        Slice s;
        if (!read_universal(kTagEnumerated, &s)) return false;
        return decode_int_be(s, value);
    }
    // Read an INTEGER and decode its value. Returns false if the tag is wrong OR
    // the value can't be decoded (e.g. empty/over-long) — matching the Kotlin
    // reference's readUniversalInt, so native is never more lenient on the
    // required version fields than KeyDescriptionParser (parity, spec §6).
    bool read_int(int* value) {
        Slice s;
        if (!read_universal(kTagInteger, &s)) return false;
        return decode_int_be(s, value);
    }
    bool read_boolean(bool* value) {
        Slice s;
        if (!read_universal(kTagBoolean, &s)) return false;
        if (s.n == 0) return false;
        *value = s.p[0] != 0;
        return true;
    }
    void skip_universal(int expected) {
        Slice s;
        read_universal(expected, &s);
    }

private:
    struct Header {
        int tag_class;
        bool constructed;
        int tag_num;
        size_t length;
    };
    bool read_header(Header* h) {
        if (remaining() < 2) return false;
        int tag_byte = buf_[pos_++] & 0xFF;
        h->tag_class = (tag_byte >> 6) & 0x03;
        h->constructed = (tag_byte & 0x20) != 0;
        int tag_num = tag_byte & 0x1F;
        if (tag_num == 0x1F) {
            tag_num = 0;
            for (;;) {
                if (remaining() < 1) return false;
                int b = buf_[pos_++] & 0xFF;
                tag_num = (tag_num << 7) | (b & 0x7F);
                if ((b & 0x80) == 0) break;
                if (tag_num > 0x10'0000) return false;
            }
        }
        h->tag_num = tag_num;
        if (remaining() < 1) return false;
        int first = buf_[pos_++] & 0xFF;
        size_t length;
        if (first < 0x80) {
            length = (size_t)first;
        } else {
            int num_len = first & 0x7F;
            if (num_len == 0 || num_len > 4 || remaining() < (size_t)num_len) return false;
            size_t n = 0;
            for (int i = 0; i < num_len; ++i) n = (n << 8) | (buf_[pos_++] & 0xFF);
            length = n;
        }
        if (length > remaining()) return false;
        h->length = length;
        return true;
    }
    static bool decode_int_be(const Slice& s, int* out) {
        if (s.n == 0 || s.n > 5) return false;
        // Shift in UNSIGNED to sign-extend a two's-complement big-endian integer
        // without UB (left-shifting a negative signed value is undefined — caught
        // by UBSAN). High bits start all-ones iff the sign bit is set.
        unsigned long long u = ((int8_t)s.p[0] < 0) ? ~0ULL : 0ULL;
        for (size_t i = 0; i < s.n; ++i) u = (u << 8) | (unsigned)(s.p[i] & 0xFF);
        long long n = (long long)u;
        if (n < (long long)INT32_MIN || n > (long long)INT32_MAX) return false;
        *out = (int)n;
        return true;
    }
    const uint8_t* buf_;
    size_t len_;
    size_t pos_;
};

DI_OBF_ATTEST __attribute__((noinline))
int parse_root_of_trust_state(const Slice& explicit_val) {
    Reader r(explicit_val.p, explicit_val.n);
    Slice seq;
    if (!r.read_universal(kTagSequence, &seq)) return -1;
    Reader s(seq.p, seq.n);
    Slice boot_key;
    if (!s.read_universal(kTagOctetString, &boot_key)) return -1;  // verifiedBootKey
    bool device_locked = false;
    if (!s.read_boolean(&device_locked)) return -1;                // deviceLocked
    (void)boot_key;
    (void)device_locked;
    int vbs;
    if (!s.read_enum(&vbs)) return -1;                             // verifiedBootState
    return (vbs >= 0 && vbs <= 3) ? vbs : -1;
}

DI_OBF_ATTEST __attribute__((noinline))
int authlist_boot_state(const Slice& blob) {
    if (blob.n == 0) return -1;
    Reader r(blob.p, blob.n);
    while (r.remaining() > 0) {
        int tag_class, tag_num;
        Slice val;
        if (!r.read_any(&tag_class, &tag_num, &val)) break;
        if (tag_class != kClassContext) continue;
        if (tag_num == kTagRootOfTrust) return parse_root_of_trust_state(val);
    }
    return -1;
}

// Copy the ASCII OCTET STRING wrapped by an EXPLICIT context tag into [out].
DI_OBF_ATTEST __attribute__((noinline))
void copy_attid_octet(const Slice& explicit_val, char* out, size_t cap) {
    Reader r(explicit_val.p, explicit_val.n);
    Slice s;
    if (!r.read_universal(kTagOctetString, &s)) return;
    size_t n = (s.n < cap - 1) ? s.n : cap - 1;
    memcpy(out, s.p, n);
    out[n] = '\0';
}

// Walk an AuthorizationList for the device-ID tags and copy each into [out].
// Additive: never clears a field already set (so tee_enforced can overwrite the
// software_enforced view by being parsed second). Fail-open: unknown/short tags
// are skipped.
DI_OBF_ATTEST __attribute__((noinline))
void extract_device_ids(const Slice& blob, KdDeviceIds* out) {
    if (blob.n == 0) return;
    Reader r(blob.p, blob.n);
    while (r.remaining() > 0) {
        int tag_class, tag_num;
        Slice val;
        if (!r.read_any(&tag_class, &tag_num, &val)) break;
        if (tag_class != kClassContext) continue;
        char* field = nullptr;
        switch (tag_num) {
            case kTagAttIdBrand: field = out->brand; break;
            case kTagAttIdDevice: field = out->device; break;
            case kTagAttIdProduct: field = out->product; break;
            case kTagAttIdManufacturer: field = out->manufacturer; break;
            case kTagAttIdModel: field = out->model; break;
            default: continue;
        }
        copy_attid_octet(val, field, 64);
        if (field[0] != '\0') out->any_present = true;
    }
}

}  // namespace

DI_OBF_ATTEST __attribute__((noinline))
void parse_keydescription(const uint8_t* p, size_t len, KdInfo* out) {
    if (p == nullptr || len == 0) return;
    int first = p[0] & 0xFF;
    if (first >= 0xA0 && first <= 0xBF) return;  // CBOR-EAT, can't decode
    Reader top(p, len);
    Slice seq;
    if (!top.read_universal(kTagSequence, &seq)) return;
    Reader s(seq.p, seq.n);
    int ver;
    if (!s.read_int(&ver)) return;                          // attestationVersion (decodable)
    // attestationSecurityLevel — capture the enum value (0 Software / 1 TEE /
    // 2 StrongBox). read_enum leaves pos_ EXACTLY where skip_universal would
    // (advances past a present tag in every case, restores on absence), so the
    // boot-state parse below is byte-for-byte unchanged (§6 parity preserved).
    int asl;
    if (s.read_enum(&asl)) out->sl = (asl >= 0 && asl <= 2) ? asl : -1;
    if (!s.read_int(&ver)) return;                          // keymasterVersion (decodable)
    s.skip_universal(kTagEnumerated);                       // keymasterSecurityLevel
    Slice chal;
    if (s.read_universal(kTagOctetString, &chal)) {         // attestationChallenge
        out->chal = chal.p;
        out->chal_len = chal.n;
    }
    s.skip_universal(kTagOctetString);                      // uniqueId
    Slice sw_enforced, tee_enforced;
    bool have_sw = s.read_universal(kTagSequence, &sw_enforced);
    bool have_tee = s.read_universal(kTagSequence, &tee_enforced);
    int tee_state = have_tee ? authlist_boot_state(tee_enforced) : -1;
    out->bs = (tee_state >= 0)                              // tee wins over sw
                  ? tee_state
                  : (have_sw ? authlist_boot_state(sw_enforced) : -1);
    if (have_sw) extract_device_ids(sw_enforced, &out->dev);
    if (have_tee) extract_device_ids(tee_enforced, &out->dev);  // tee overwrites sw
}

DI_OBF_ATTEST __attribute__((noinline))
void kd_from_extensions(const uint8_t* exts, size_t len, KdInfo* out) {
    Reader outer(exts, len);
    Slice list;
    if (!outer.read_universal(kTagSequence, &list)) return;
    Reader r(list.p, list.n);
    while (r.remaining() > 0) {
        Slice ext;
        if (!r.read_universal(kTagSequence, &ext)) break;     // one Extension
        Reader e(ext.p, ext.n);
        Slice oid;
        if (!e.read_universal(kTagOid, &oid)) continue;
        if (oid.n != sizeof(kKeyDescOid) ||
            memcmp(oid.p, kKeyDescOid, sizeof(kKeyDescOid)) != 0) {
            continue;
        }
        e.skip_universal(kTagBoolean);                        // critical (optional)
        Slice octet;
        if (!e.read_universal(kTagOctetString, &octet)) return;  // extnValue
        parse_keydescription(octet.p, octet.n, out);
        return;
    }
}

int attest_boot_state(const uint8_t* ext, size_t len) {
    if (ext == nullptr || len == 0 || len > kMaxCert) return -1;
    Reader outer(ext, len);
    Slice unwrapped;
    if (!outer.read_universal(kTagOctetString, &unwrapped)) return -1;
    KdInfo kd;
    parse_keydescription(unwrapped.p, unwrapped.n, &kd);
    return kd.bs;
}

}  // namespace dicore
