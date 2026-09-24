#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// X.509 certificate-chain verification. A thin in-house facade over the vendored
// verifier so the detectors never reference the underlying engine directly.
namespace dicore::crypto {

// A certificate chain, built by appending DER certificates leaf-first.
class CertChain {
public:
    CertChain();
    ~CertChain();
    CertChain(const CertChain&) = delete;
    CertChain& operator=(const CertChain&) = delete;

    // Append one DER-encoded certificate. Returns 0 on success.
    int add_der(const uint8_t* der, size_t len);

    // Verify this chain against [trust] (a chain of trusted roots). Returns 0 if
    // it terminates at a trusted root; *flags carries the failure bitmask.
    int verify(CertChain& trust, uint32_t* flags);

    // Serial-number bytes of every certificate, leaf first.
    std::vector<std::vector<uint8_t>> serials() const;

    // Raw v3-extensions bytes of the leaf. Valid while this chain is alive.
    bool leaf_extensions(const uint8_t** p, size_t* len) const;

private:
    void* impl_;
};

// SubjectPublicKeyInfo (raw DER) of a single DER certificate; empty on failure.
std::vector<uint8_t> spki_of_der(const uint8_t* der, size_t len);

}  // namespace dicore::crypto
