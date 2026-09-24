// Host test for the APK Signing Block parser, run over a REAL signed APK
// (a small committed v2-signed fixture) via ApkMap.open_memory. Asserts the extracted
// v2 signer certificate digest matches an independent oracle (keytool exportcert |
// sha256sum). Path defaults to the committed fixture (runner cwd = repo root); argv[1] overrides.
#include "dicore/detectors/apk/container/apkmap.h"
#include "dicore/detectors/apk/identity/sigblock_parser.h"
#include "dicore/detectors/apk/container/zip_parser.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    using namespace dicore;
    const char* path = argc > 1 ? argv[1] :
        "deviceintelligence/src/main/cpp/test/detectors/apk/testdata/signed-sample.apk.bin";

    FILE* f = std::fopen(path, "rb");
    assert(f && "signed-APK fixture not found (run from repo root)");
    std::fseek(f, 0, SEEK_END); long sz = std::ftell(f); std::fseek(f, 0, SEEK_SET);
    assert(sz > 0);
    std::vector<uint8_t> buf((size_t)sz);
    assert(std::fread(buf.data(), 1, buf.size(), f) == buf.size());
    std::fclose(f);

    ApkMap apk;
    assert(apk.open_memory(buf.data(), buf.size()));
    zip::CentralDirInfo cdi;
    assert(zip::find_central_directory(apk, &cdi) && cdi.present);

    sigblock::SignerCerts certs;
    assert(sigblock::extract_signer_certs(apk, cdi, &certs));
    assert(certs.source == sigblock::SignerCerts::Source::kV2);      // fixture is v2-signed
    assert(!certs.cert_sha256_hex.empty());

    // apksigner: Signer #1 certificate SHA-256 digest.
    // Independently verified: keytool -exportcert ... | sha256sum.
    const std::string expected = "57a4ce54ae9959b55b1773594c66229fffb75a48ff1ad4ce3069d9b80eed00f4";
    bool matched = false;
    for (const auto& c : certs.cert_sha256_hex) if (c == expected) matched = true;
    assert(matched && "signer cert SHA-256 must match apksigner");

    std::printf("test_sigblock_parser OK (source=%d, %zu cert(s))\n",
                (int)certs.source, certs.cert_sha256_hex.size());
    return 0;
}
