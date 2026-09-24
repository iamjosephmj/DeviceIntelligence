// cloner_probe_jni.cpp — JNI binding for the F13 cloner probe.
//
// Spec 03 port: the cloner DECISION now lives entirely in native. Kotlin used to
// drive five raw readers and make the comparisons itself (apk-path component
// match, data-dir owner membership, kernel-vs-Java UID). That policy is now here
// in `nativeClonerVerdict`, which composes the dicore::cloner readers, decides,
// and returns ready-to-marshal Finding records. Kotlin only wraps the records
// into Finding objects — no decision survives in the JVM.

#include "dicore/detectors/cloner/cloner_probe.h"

#include <jni.h>
#include <string>
#include <vector>

namespace {

// Records use US (0x1f) as the field separator so embedded paths / mount dumps
// (which contain '|', '/', '=') never collide with the framing. Each record is:
//   kind \x1f SEVERITY \x1f message \x1f k=v \x1f k=v ...
constexpr char kFS = '\x1f';

std::string make_record(const char* kind, const char* severity, const char* message,
                        const std::vector<std::string>& details) {
    std::string r;
    r.reserve(128);
    r += kind;       r += kFS;
    r += severity;   r += kFS;
    r += message;
    for (const auto& kv : details) { r += kFS; r += kv; }
    return r;
}

// Is [pkg] present as a full element of a '|'-separated [list]?
bool list_has_pkg(const char* list, const char* pkg) {
    std::string hay(list);
    std::string needle(pkg);
    if (needle.empty()) return false;
    size_t pos = 0;
    while (pos <= hay.size()) {
        size_t bar = hay.find('|', pos);
        size_t end = (bar == std::string::npos) ? hay.size() : bar;
        if (hay.compare(pos, end - pos, needle) == 0) return true;
        if (bar == std::string::npos) break;
        pos = bar + 1;
    }
    return false;
}

} // namespace

namespace dicore {

// Native cloner verdict core (shared by the Kotlin-driven JNI and the native
// orchestrator) — all three signals decided in C++:
//   apk_path_mismatch (CRITICAL), data_dir_mount_invalid (CRITICAL),
//   uid_mismatch (HIGH). [javaUid] is the only Java-level input (Process.myUid());
//   the UID signal is inherently a kernel-vs-Java comparison so the Java value
//   must be supplied. Read failures degrade to "no signal" (never a finding).
//   Each kind is emitted at most once.
std::vector<std::string> cloner_verdict_records(const std::string& pkgStr, int javaUid) {
    const char* pkg = pkgStr.c_str();
    std::vector<std::string> records;
    char buf[1024];

    // ---- Signal 1: apk_path_mismatch (CRITICAL), emitted once ----------------
    bool apk_emitted = false;
    if (dicore::cloner::find_foreign_apk_in_maps(pkg, buf, sizeof(buf)) > 0) {
        records.push_back(make_record(
            "apk_path_mismatch", "CRITICAL",
            "Foreign APK mapping detected in process address space",
            {std::string("signal=foreign_apk_in_maps"),
             std::string("expected_package=") + pkg,
             std::string("foreign_apk_path=") + buf}));
        apk_emitted = true;
    }
    if (!apk_emitted) {
        char first[512];
        int n = dicore::cloner::read_apk_path_from_maps(first, sizeof(first));
        if (n > 0 && !dicore::cloner::path_has_pkg_component(first, pkg)) {
            records.push_back(make_record(
                "apk_path_mismatch", "CRITICAL",
                "Process's first base.apk mapping does not belong to our package",
                {std::string("signal=first_apk_mapping"),
                 std::string("expected_package=") + pkg,
                 std::string("observed_apk_path=") + first}));
        }
    }

    // ---- Signal 2: data_dir_mount_invalid (CRITICAL), emitted once -----------
    bool mount_emitted = false;
    if (dicore::cloner::find_suspicious_mount(pkg, buf, sizeof(buf)) > 0) {
        // buf is "fstype=...|source=...|mount=..." — split each k=v into a detail.
        std::vector<std::string> details{std::string("signal=suspicious_mount"),
                                         std::string("expected_package=") + pkg};
        std::string dump(buf);
        size_t pos = 0;
        while (pos < dump.size()) {
            size_t bar = dump.find('|', pos);
            size_t end = (bar == std::string::npos) ? dump.size() : bar;
            std::string kv = dump.substr(pos, end - pos);
            if (kv.find('=') != std::string::npos) details.push_back(kv);
            if (bar == std::string::npos) break;
            pos = bar + 1;
        }
        records.push_back(make_record(
            "data_dir_mount_invalid", "CRITICAL",
            "Suspicious mount touches our data dir (tmpfs or foreign-source)",
            details));
        mount_emitted = true;
    }
    if (!mount_emitted) {
        char owners[1024];
        int n = dicore::cloner::list_data_dir_owners(owners, sizeof(owners));
        if (n > 0 && !list_has_pkg(owners, pkg)) {
            // Present the owners as a comma-separated list (drop empty fields).
            std::string csv;
            std::string raw(owners);
            size_t pos = 0;
            while (pos < raw.size()) {
                size_t bar = raw.find('|', pos);
                size_t end = (bar == std::string::npos) ? raw.size() : bar;
                if (end > pos) { if (!csv.empty()) csv += ','; csv += raw.substr(pos, end - pos); }
                if (bar == std::string::npos) break;
                pos = bar + 1;
            }
            records.push_back(make_record(
                "data_dir_mount_invalid", "CRITICAL",
                "Process is in a mount namespace that doesn't include our data dir",
                {std::string("signal=foreign_mount_namespace"),
                 std::string("expected_package=") + pkg,
                 std::string("mount_namespace_owners=") + csv}));
        }
    }

    // ---- Signal 3: uid_mismatch (HIGH) --------------------------------------
    int kernel_uid = dicore::cloner::read_kernel_uid_from_status();
    if (kernel_uid >= 0 && kernel_uid != (int)javaUid) {
        records.push_back(make_record(
            "uid_mismatch", "HIGH",
            "Kernel-reported UID disagrees with Java-level Process.myUid()",
            {std::string("java_uid=") + std::to_string((int)javaUid),
             std::string("kernel_uid=") + std::to_string(kernel_uid)}));
    }
    return records;
}

}  // namespace dicore

