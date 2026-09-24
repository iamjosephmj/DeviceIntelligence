#include "dicore/detectors/apk/identity/dex_provenance.h"

#include "dicore/orchestrator/record_util.h"  // kFS
#include "dicore/platform/framework_shim.h"
#include "dicore/platform/svc_io.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace dicore {

namespace {

bool starts_with(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

// Attacker-writable roots a legit app never loads a dex from. The app's own dex
// lives under /data/app; framework jars under /system, /apex, /vendor — none of
// which are listed here, so those never flag.
bool attacker_writable(const std::string& path) {
    return starts_with(path, "/data/local/tmp") ||
           starts_with(path, "/sdcard") ||
           starts_with(path, "/storage/emulated") ||
           starts_with(path, "/storage/self") ||
           starts_with(path, "/mnt/sdcard");
}

// How many in-memory dex regions the kernel is showing us.
//
// ART names the anonymous mapping backing a ByteBuffer-loaded dex
// `[anon:dalvik-DEX data]`. It is mapped r--p, never executable, which is why
// every executable-code path in the environment maps scan is blind to it — and why
// this count has to be taken here rather than folded into the foreign-code scan.
//
// The count is a FLOOR, not an exact tally: ART dedupes identical dex bytes, so
// two loaders over the same buffer share one mapping. That asymmetry is
// deliberate and it fails SAFE — the count can under-report and cause a miss, but
// it cannot over-report and manufacture an accusation.
size_t in_memory_dex_regions() {
    // B3: raw-syscall read — the dex-injection detector this feeds must not be
    // blindable by a libc stdio hook hiding the `[anon:dalvik-DEX data]` line.
    std::string maps;
    if (!svc::read_file("/proc/self/maps", &maps)) {
        return 0;                       // unreadable -> report nothing, never guess
    }
    size_t n = 0;
    svc::LineCursor cur(maps);
    std::string line;
    while (cur.next(&line)) {
        if (line.find("anon:dalvik-DEX data") != std::string::npos) ++n;
    }
    return n;
}

}  // namespace

std::vector<std::string> dex_provenance_records() {
    std::vector<std::string> out;
    size_t reachable_in_memory = 0;

    // "<loaderClass>\x1f<dexPathOrEmpty>\x1f<appLoaderInChain 0|1>"
    for (const auto& e : fw_dex_entries()) {
        size_t s1 = e.find(kFS);
        std::string loader = (s1 == std::string::npos) ? e : e.substr(0, s1);
        std::string rest = (s1 == std::string::npos) ? std::string() : e.substr(s1 + 1);
        size_t s2 = rest.find(kFS);
        std::string path = (s2 == std::string::npos) ? rest : rest.substr(0, s2);
        std::string sees = (s2 == std::string::npos) ? std::string("1") : rest.substr(s2 + 1);

        if (!path.empty()) {
            // A dex with a real path: judged purely on where that path lives.
            if (attacker_writable(path)) {
                out.push_back(std::string("foreign_dex_loaded") + kFS + "CRITICAL" + kFS +
                              "path=" + path + " loader=" + loader);
            }
            continue;
        }

        // In-memory dex (no backing file). A bare empty path is NOT evidence on its
        // own — legitimate apps use InMemoryDexClassLoader for dynamic-feature
        // delivery and DI frameworks, which is why the old `in_memory_dex_loaded`
        // signal was removed as false-positive prone.
        //
        // What IS evidence: an in-memory dex whose loader chain does not include the
        // app's own class loader. A feature module is parented into the app loader
        // precisely so its code can call back into the app; code that cannot see the
        // app it was loaded into is not a feature module.
        ++reachable_in_memory;
        if (sees == "0") {
            out.push_back(std::string("dex_foreign_loader") + kFS + "HIGH" + kFS +
                          "in-memory dex whose loader chain cannot see the app's own "
                          "classes loader=" + loader);
        }
    }

    // The detached case: a dex mapping the kernel shows us that no reachable loader
    // claims. Nothing Java-side references it — that is exactly what an injected,
    // frida-held InMemoryDexClassLoader looks like.
    //
    // Compared one-directionally on purpose. maps > reachable is the accusation;
    // maps < reachable is the ordinary consequence of ART's dedupe and is ignored.
    const size_t mapped = in_memory_dex_regions();
    if (mapped > reachable_in_memory) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "mapped_in_memory_dex=%zu reachable=%zu unaccounted=%zu",
                 mapped, reachable_in_memory, mapped - reachable_in_memory);
        out.push_back(std::string("dex_unaccounted_in_memory") + kFS + "HIGH" + kFS + detail);
    }

    return out;
}

}  // namespace dicore
