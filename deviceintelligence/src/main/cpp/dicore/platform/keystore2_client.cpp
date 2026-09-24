#include "dicore/platform/keystore2_client.h"

// libbinder_ndk is the only stable NDK surface for a system service, but its stub
// exists only at API 29+, so this minSdk-28 library must NOT link it. We dlopen it
// at runtime and dlsym the handful of entry points we need; on a pre-31 device (no
// keystore2) the dlopen simply fails and every call fail-opens. Headers are pulled
// in for the opaque TYPES and constants only — we never reference the functions
// directly (that would create a link-time dependency).
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <android/binder_status.h>
// NB: android/binder_manager.h (AServiceManager_*) is NOT shipped in the NDK —
// it's a system API. We resolve AServiceManager_checkService by name via dlsym
// and declare its pointer type ourselves, so the header isn't needed.

#include <dlfcn.h>
#include <cstring>

namespace dicore::ks2 {
namespace {

// SAFETY GATE. Service acquisition, tag encoding, and parcel plumbing below are
// real and compiled. The exact stable-AIDL parcelable field order + transaction
// codes (KS2_VERIFY) still need on-device confirmation against this device's
// keystore2 AIDL version. Until that passes the E2E fixture parity test, every
// entry point returns empty (fail-open), so wiring this file in changes nothing.
constexpr bool kVerified = false;

constexpr const char* kServiceName = "android.system.keystore2.IKeystoreService/default";

// ---- dlopen'd libbinder_ndk entry points ------------------------------------
struct Binder {
    void* h = nullptr;
    AIBinder* (*checkService)(const char*) = nullptr;
    binder_status_t (*prepare)(AIBinder*, AParcel**) = nullptr;
    binder_status_t (*transact)(AIBinder*, transaction_code_t, AParcel**, AParcel**, binder_flags_t) = nullptr;
    void (*decStrong)(AIBinder*) = nullptr;
    binder_status_t (*wI32)(AParcel*, int32_t) = nullptr;
    binder_status_t (*wI64)(AParcel*, int64_t) = nullptr;
    binder_status_t (*wStr)(AParcel*, const char*, int32_t) = nullptr;
    binder_status_t (*wBytes)(AParcel*, const int8_t*, int32_t) = nullptr;
    binder_status_t (*rI32)(const AParcel*, int32_t*) = nullptr;
    binder_status_t (*rBinder)(const AParcel*, AIBinder**) = nullptr;
    binder_status_t (*rBytes)(const AParcel*, void*, AParcel_byteArrayAllocator) = nullptr;
    void (*pDelete)(AParcel*) = nullptr;
    bool ok() const {
        return h && checkService && prepare && transact && decStrong && wI32 && wI64 &&
               wStr && wBytes && rI32 && rBinder && rBytes && pDelete;
    }
};

const Binder& binder() {
    static Binder b = [] {
        Binder x;
        x.h = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
        if (!x.h) return x;
        auto S = [&](auto& fp, const char* n) {
            fp = reinterpret_cast<std::remove_reference_t<decltype(fp)>>(dlsym(x.h, n));
        };
        S(x.checkService, "AServiceManager_checkService");
        S(x.prepare,      "AIBinder_prepareTransaction");
        S(x.transact,     "AIBinder_transact");
        S(x.decStrong,    "AIBinder_decStrong");
        S(x.wI32,         "AParcel_writeInt32");
        S(x.wI64,         "AParcel_writeInt64");
        S(x.wStr,         "AParcel_writeString");
        S(x.wBytes,       "AParcel_writeByteArray");
        S(x.rI32,         "AParcel_readInt32");
        S(x.rBinder,      "AParcel_readStrongBinder");
        S(x.rBytes,       "AParcel_readByteArray");
        S(x.pDelete,      "AParcel_delete");
        return x;
    }();
    return b;
}

// ---- KeyMint tag / enum constants (android.hardware.security.keymint) --------
// tag = TagType | id. KS2_VERIFY: stable across KeyMint V1..V4.
namespace TagType {
constexpr uint32_t ENUM = 0x10000000u, ENUM_REP = 0x20000000u,
                   BOOL = 0x70000000u, BYTES = 0x90000000u;
}
namespace Tag {
constexpr int32_t PURPOSE                     = (int32_t)(TagType::ENUM_REP | 1u);
constexpr int32_t ALGORITHM                   = (int32_t)(TagType::ENUM | 2u);
constexpr int32_t DIGEST                      = (int32_t)(TagType::ENUM_REP | 5u);
constexpr int32_t EC_CURVE                    = (int32_t)(TagType::ENUM | 10u);
constexpr int32_t NO_AUTH_REQUIRED            = (int32_t)(TagType::BOOL | 503u);
constexpr int32_t ATTESTATION_CHALLENGE       = (int32_t)(TagType::BYTES | 708u);
constexpr int32_t ATTESTATION_ID_BRAND        = (int32_t)(TagType::BYTES | 710u);
constexpr int32_t ATTESTATION_ID_DEVICE       = (int32_t)(TagType::BYTES | 711u);
constexpr int32_t ATTESTATION_ID_PRODUCT      = (int32_t)(TagType::BYTES | 712u);
constexpr int32_t ATTESTATION_ID_MANUFACTURER = (int32_t)(TagType::BYTES | 716u);
constexpr int32_t ATTESTATION_ID_MODEL        = (int32_t)(TagType::BYTES | 717u);
}
constexpr int32_t KEY_PURPOSE_SIGN = 2, ALGORITHM_EC = 3, DIGEST_SHA_2_256 = 4, EC_CURVE_P_256 = 1;
constexpr int32_t SECLEVEL_TEE = 1, SECLEVEL_STRONGBOX = 2, DOMAIN_APP = 0;

// Transaction codes = FIRST_CALL_TRANSACTION + method index (AIDL decl order).
// KS2_VERIFY against the device's AIDL — method order is the contract.
constexpr transaction_code_t TX_getSecurityLevel = FIRST_CALL_TRANSACTION + 0;  // IKeystoreService
constexpr transaction_code_t TX_generateKey      = FIRST_CALL_TRANSACTION + 1;  // IKeystoreSecurityLevel

bool vec_alloc(void* arrayData, int32_t length, int8_t** outBuffer) {
    auto* v = static_cast<std::vector<uint8_t>*>(arrayData);
    if (length < 0) { v->clear(); *outBuffer = nullptr; return true; }
    v->resize((size_t)length);
    *outBuffer = reinterpret_cast<int8_t*>(v->data());
    return true;
}

// KS2_VERIFY: KeyParameter{ int tag; KeyParameterValue value } — the value is a
// union whose parcel form is [i32 non-null][i32 size][i32 union-tag][member].
// These helpers are the integration point; they emit nothing until the union
// ordinals are confirmed on-device (returning false keeps the scaffold inert).
bool write_kp_int(const Binder&, AParcel*, int32_t /*tag*/, int32_t /*val*/) { return false; }
bool write_kp_bytes(const Binder&, AParcel*, int32_t /*tag*/, const uint8_t*, size_t) { return false; }

}  // namespace

bool available() {
    if (!kVerified) return false;
    const Binder& b = binder();
    if (!b.ok()) return false;
    AIBinder* svc = b.checkService(kServiceName);
    if (!svc) return false;
    b.decStrong(svc);
    return true;
}

std::vector<std::vector<uint8_t>> generate_attested_key(
    const std::string& alias, const uint8_t* nonce, size_t nonce_len,
    const DeviceProps& props, Level level) {
    std::vector<std::vector<uint8_t>> chain;
    if (!kVerified) return chain;
    const Binder& b = binder();
    if (!b.ok()) return chain;

    AIBinder* svc = b.checkService(kServiceName);
    if (!svc) return chain;

    // 1) getSecurityLevel(level) -> IKeystoreSecurityLevel.
    AIBinder* seclevel = nullptr;
    {
        AParcel* in = nullptr; AParcel* out = nullptr;
        if (b.prepare(svc, &in) == STATUS_OK) {
            b.wI32(in, level == Level::kStrongBox ? SECLEVEL_STRONGBOX : SECLEVEL_TEE);
            if (b.transact(svc, TX_getSecurityLevel, &in, &out, 0) == STATUS_OK && out) {
                int32_t ex = 0; b.rI32(out, &ex);      // binder exception header
                b.rBinder(out, &seclevel);
            }
        }
        if (out) b.pDelete(out);
    }
    if (!seclevel) { b.decStrong(svc); return chain; }

    // 2) generateKey(KeyDescriptor{APP,-1,alias}, null, KeyParameter[]{...}, 0, []).
    {
        AParcel* in = nullptr; AParcel* out = nullptr;
        if (b.prepare(seclevel, &in) == STATUS_OK) {
            b.wI32(in, 1);                       // KeyDescriptor non-null (KS2_VERIFY field order)
            b.wI32(in, DOMAIN_APP);
            b.wI64(in, -1);                      // nspace
            b.wStr(in, alias.c_str(), (int32_t)alias.size());
            b.wI32(in, -1);                      // blob = null
            b.wI32(in, 0);                       // attestationKey = null
            b.wI32(in, 0);                       // KeyParameter[] length (KS2_VERIFY)
            write_kp_int(b, in, Tag::ALGORITHM, ALGORITHM_EC);
            write_kp_int(b, in, Tag::EC_CURVE, EC_CURVE_P_256);
            write_kp_int(b, in, Tag::DIGEST, DIGEST_SHA_2_256);
            write_kp_int(b, in, Tag::PURPOSE, KEY_PURPOSE_SIGN);
            write_kp_int(b, in, Tag::NO_AUTH_REQUIRED, 1);
            write_kp_bytes(b, in, Tag::ATTESTATION_CHALLENGE, nonce, nonce_len);
            if (props.any()) {
                auto id = [&](int32_t t, const std::string& s) {
                    if (!s.empty()) write_kp_bytes(b, in, t, reinterpret_cast<const uint8_t*>(s.data()), s.size());
                };
                id(Tag::ATTESTATION_ID_BRAND, props.brand);
                id(Tag::ATTESTATION_ID_DEVICE, props.device);
                id(Tag::ATTESTATION_ID_PRODUCT, props.product);
                id(Tag::ATTESTATION_ID_MANUFACTURER, props.manufacturer);
                id(Tag::ATTESTATION_ID_MODEL, props.model);
            }
            b.wI32(in, 0);                       // flags
            b.wBytes(in, nullptr, 0);            // entropy = []

            if (b.transact(seclevel, TX_generateKey, &in, &out, 0) == STATUS_OK && out) {
                int32_t ex = 0; b.rI32(out, &ex);
                // KS2_VERIFY: KeyMetadata -> certificate (leaf) + certificateChain.
                std::vector<uint8_t> leaf; b.rBytes(out, &leaf, vec_alloc);
                if (!leaf.empty()) chain.push_back(std::move(leaf));
                std::vector<uint8_t> rest; b.rBytes(out, &rest, vec_alloc);
                if (!rest.empty()) chain.push_back(std::move(rest));
            }
        }
        if (in) b.pDelete(in);
        if (out) b.pDelete(out);
    }

    b.decStrong(seclevel);
    b.decStrong(svc);
    return chain;
}

std::vector<uint8_t> sign(const std::string& alias, const uint8_t* msg, size_t msg_len) {
    std::vector<uint8_t> sig;
    if (!kVerified) return sig;
    // KS2_VERIFY: getSecurityLevel + createOperation(KeyDescriptor{alias},
    // [DIGEST=SHA256, PURPOSE=SIGN], forced=false) -> IKeystoreOperation, then
    // finish(input=msg, signature=null) -> signature bytes. Same parcelable
    // confirmations as generate_attested_key.
    (void)alias; (void)msg; (void)msg_len;
    return sig;
}

}  // namespace dicore::ks2
