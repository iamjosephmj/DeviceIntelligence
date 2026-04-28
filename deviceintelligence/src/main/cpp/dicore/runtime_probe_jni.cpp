// JNI bindings for F16/F17 runtime/root probes.
//
// Two helpers, both kept in C++ rather than reimplemented in Kotlin
// for the same reasons the rest of dicore does:
//   - `__system_property_get` is the canonical Android API for
//     reading `ro.*` properties; calling it directly avoids the
//     hidden-API reflection into `android.os.SystemProperties` and
//     avoids spawning a `getprop` subprocess.
//   - `/proc/self/maps` is a procfs file the kernel materializes on
//     each read; doing the open/read in C++ side-steps the Kotlin
//     IO dispatchers and lets us read it as a single byte buffer.

#include "log.h"

#include <jni.h>
#include <sys/system_properties.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace dicore {

namespace {

// Reads the named property via __system_property_get. Returns true and
// writes to *out_value on success; returns false when the property is
// unset (length 0). PROP_VALUE_MAX is 92 bytes including the null
// terminator on every supported Android version, so a fixed buffer
// is fine.
bool read_system_property(const char* name, std::string* out_value) {
    char buf[PROP_VALUE_MAX] = {0};
    int len = __system_property_get(name, buf);
    if (len <= 0) return false;
    out_value->assign(buf, static_cast<size_t>(len));
    return true;
}

// Reads /proc/self/maps in full. The file is materialized by the
// kernel on each read; on a typical app it's 200-500 KB. We grow the
// buffer geometrically rather than trying to stat() the file (procfs
// lies about size) and stop on a short read or EOF.
bool read_proc_self_maps(std::string* out) {
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) {
        RLOGW("procSelfMaps: fopen failed errno=%d", errno);
        return false;
    }
    std::vector<char> buf;
    buf.reserve(256 * 1024);
    char chunk[8192];
    while (true) {
        size_t n = std::fread(chunk, 1, sizeof(chunk), f);
        if (n == 0) break;
        buf.insert(buf.end(), chunk, chunk + n);
        if (n < sizeof(chunk)) break;
    }
    std::fclose(f);
    out->assign(buf.data(), buf.size());
    return true;
}

}  // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_systemProperty(
        JNIEnv* env, jclass, jstring jname) {
    if (!jname) return nullptr;
    const char* name = env->GetStringUTFChars(jname, nullptr);
    if (!name) return nullptr;
    std::string value;
    bool ok = read_system_property(name, &value);
    env->ReleaseStringUTFChars(jname, name);
    if (!ok) return nullptr;
    return env->NewStringUTF(value.c_str());
}

JNIEXPORT jstring JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_procSelfMaps(
        JNIEnv* env, jclass) {
    std::string contents;
    if (!read_proc_self_maps(&contents)) return nullptr;
    return env->NewStringUTF(contents.c_str());
}

}  // extern "C"

}  // namespace dicore
