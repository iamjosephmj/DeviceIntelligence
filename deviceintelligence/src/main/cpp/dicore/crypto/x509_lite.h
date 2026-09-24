#pragma once

#include <cstddef>
#include <cstdint>

// Minimal, bounds-checked X.509 (DER) field extractor — the self-owned
// replacement for the retired vendored X.509 engine in certchain. It PARSES ONLY (no signature
// verification): it locates the byte ranges the attestation detectors need
// (serial, issuer/subject Name, SubjectPublicKeyInfo, v3 extensions). The
// cryptographic chain verification is the BACKEND's authority (ChainVerifier);
// on-device trust is a structural DN-chaining check built on these views
// (see certchain.cpp). Runs on attacker-influenced bytes, so every read is
// bounds-checked and any malformation yields ok=false (fail-open — never an
// affirmatively-wrong value).
namespace dicore::crypto {

// Byte-views INTO the caller's DER buffer (valid only while it lives). Ranges
// match the retired engine's semantics so kd_from_extensions et al. are unaffected:
//   serial  = INTEGER content bytes (incl any leading 0x00), like the engine's serial.p
//   issuer/subject = the whole Name SEQUENCE element (tag+len+value)
//   spki    = the whole SubjectPublicKeyInfo SEQUENCE element (== the engine's pk_raw)
//   exts    = the Extensions SEQUENCE element (starts at 0x30), i.e. the [3]
//             EXPLICIT wrapper stripped — exactly what the engine's v3_ext pointed to.
struct CertView {
    bool ok = false;
    const uint8_t* serial = nullptr;  size_t serial_len = 0;
    const uint8_t* issuer = nullptr;  size_t issuer_len = 0;
    const uint8_t* subject = nullptr; size_t subject_len = 0;
    const uint8_t* spki = nullptr;    size_t spki_len = 0;
    const uint8_t* exts = nullptr;    size_t exts_len = 0;   // 0/nullptr if no v3 exts
};

CertView x509_parse(const uint8_t* der, size_t len);

}  // namespace dicore::crypto
