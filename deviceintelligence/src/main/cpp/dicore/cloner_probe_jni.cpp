// cloner_probe_jni.cpp — JNI bindings for the F13 cloner probe.
//
// Each native is a thin wrapper around dicore::cloner: the parsing
// and policy live there; this file only marshals to/from JVM types.

#include "cloner_probe.h"

#include <jni.h>

extern "C" {

// Returns the path of the first "/base.apk" mapping in
// /proc/self/maps, or null if none was found / read failed.
// Diagnostic only — see [nativeForeignApkInMaps] for the policy
// signal.
JNIEXPORT jstring JNICALL
Java_tech_thessemaj_deviceintelligence_internal_ClonerDetector_nativeApkPathFromMaps(
    JNIEnv* env, jclass) {
    char buf[512];
    int n = dicore::cloner::read_apk_path_from_maps(buf, sizeof(buf));
    if (n <= 0) return nullptr;
    return env->NewStringUTF(buf);
}

// Returns the first ".apk" mapping in /proc/self/maps whose path
// does NOT carry [packageName] as a path component, or null if
// every apk mapping belongs to us. The Kotlin facade treats a
// non-null result as decisive cloner evidence.
JNIEXPORT jstring JNICALL
Java_tech_thessemaj_deviceintelligence_internal_ClonerDetector_nativeForeignApkInMaps(
    JNIEnv* env, jclass, jstring jpkg) {
    if (!jpkg) return nullptr;
    const char* pkg = env->GetStringUTFChars(jpkg, nullptr);
    if (!pkg) return nullptr;

    char buf[512];
    int n = dicore::cloner::find_foreign_apk_in_maps(pkg, buf, sizeof(buf));
    env->ReleaseStringUTFChars(jpkg, pkg);
    if (n <= 0) return nullptr;
    return env->NewStringUTF(buf);
}

// Returns "|"-separated list of package names extracted from app
// data dir mount-points in /proc/self/mountinfo, or null if no
// such mount-points were found / read failed. The Kotlin facade
// asserts our package name appears in the returned set.
JNIEXPORT jstring JNICALL
Java_tech_thessemaj_deviceintelligence_internal_ClonerDetector_nativeDataDirOwnerPackages(
    JNIEnv* env, jclass) {
    char buf[1024];
    int n = dicore::cloner::list_data_dir_owners(buf, sizeof(buf));
    if (n <= 0) return nullptr;
    return env->NewStringUTF(buf);
}

// Returns a "fstype=...|mount=...|source=...[|host_pkg=...]" dump
// describing the first suspicious mount that touches [packageName],
// or null if none was found / read failed.
JNIEXPORT jstring JNICALL
Java_tech_thessemaj_deviceintelligence_internal_ClonerDetector_nativeSuspiciousMountFor(
    JNIEnv* env, jclass, jstring jpkg) {
    if (!jpkg) return nullptr;
    const char* pkg = env->GetStringUTFChars(jpkg, nullptr);
    if (!pkg) return nullptr;

    char buf[512];
    int n = dicore::cloner::find_suspicious_mount(pkg, buf, sizeof(buf));
    env->ReleaseStringUTFChars(jpkg, pkg);
    if (n <= 0) return nullptr;
    return env->NewStringUTF(buf);
}

// Returns the kernel-reported real UID from /proc/self/status's
// "Uid:" line, or -1 on read / parse failure.
JNIEXPORT jint JNICALL
Java_tech_thessemaj_deviceintelligence_internal_ClonerDetector_nativeKernelUidFromStatus(
    JNIEnv*, jclass) {
    return static_cast<jint>(dicore::cloner::read_kernel_uid_from_status());
}

}  // extern "C"
