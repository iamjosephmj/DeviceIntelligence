// Host test for the ZIP parser, driven over an in-memory ZIP via ApkMap.open_memory
// (a small real archive built by python zipfile with a STORED + a DEFLATED entry).
// Exercises central-directory discovery, raw entry read, and the decompressed-hash
// path (which runs the self-owned inflater). Build via native-unit-tests.sh.
#include "dicore/detectors/apk/container/apkmap.h"
#include "dicore/detectors/apk/container/zip_parser.h"
#include "test_zip_data.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int main() {
    using namespace dicore;

    ApkMap apk;
    assert(apk.open_memory(kZip, kZipLen));

    zip::CentralDirInfo cdi;
    assert(zip::find_central_directory(apk, &cdi));
    assert(cdi.present && cdi.total_entries == 2);

    // Raw read of the STORED entry returns its exact bytes.
    std::vector<uint8_t> raw;
    assert(zip::read_entry_raw(apk, cdi, kStoredName, &raw));
    assert(raw.size() == kStoredContentLen);

    // Decompressed-hash of the DEFLATED entry == sha256 of the original content
    // (this drives the owned inflater end to end through the ZIP path).
    std::string h;
    assert(zip::hash_entry_decompressed(apk, cdi, kDeflName, &h));
    assert(h == kDeflSha);
    // STORED entry decompressed-hash == sha256 of its bytes (method-0 path).
    std::string hs;
    assert(zip::hash_entry_decompressed(apk, cdi, kStoredName, &hs));
    assert(hs == kStoredSha);

    // hash_all_entries enumerates both, with correct methods.
    int count = 0; bool sawStored = false, sawDefl = false;
    zip::hash_all_entries(apk, cdi, [&](const zip::EntryHash& e) {
        ++count;
        if (e.name == kStoredName) { sawStored = true; assert(e.method == 0); }
        if (e.name == kDeflName)   { sawDefl = true;   assert(e.method == 8); }
    });
    assert(count == 2 && sawStored && sawDefl);

    // Missing entry -> false.
    std::vector<uint8_t> none;
    assert(!zip::read_entry_raw(apk, cdi, "does/not/exist", &none));

    // Malformed: a truncated buffer has no End-Of-Central-Directory record.
    { ApkMap a2; assert(a2.open_memory(kZip, 16));
      zip::CentralDirInfo c2; assert(!zip::find_central_directory(a2, &c2)); }
    // Zero-length buffer.
    { ApkMap a3; a3.open_memory(kZip, 0);
      zip::CentralDirInfo c3; assert(!zip::find_central_directory(a3, &c3)); }

    std::printf("test_zip_parser OK\n");
    return 0;
}
