// emu_probe_jni.cpp — JNI bindings for the F12 CPU emulator probe.
//
// One probe call drives both natives below: we cache the result in
// a process-global so the Kotlin side can ask for `decisive` and
// `rawSignals` without paying for two probes. The probe itself is
// idempotent and cheap (a handful of register reads), so the cache
// is purely cosmetic.

#include "emu_probe.h"

#include <jni.h>
#include <mutex>

namespace {

std::once_flag g_probe_once;
dicore::emu::Signals g_cached{};

const dicore::emu::Signals& cached_probe() {
    std::call_once(g_probe_once, [] {
        g_cached = dicore::emu::probe();
    });
    return g_cached;
}

}  // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_internal_EmulatorProbe_nativeEmulatorDecisive(
    JNIEnv*, jclass) {
    return cached_probe().decisive ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_io_ssemaj_deviceintelligence_internal_EmulatorProbe_nativeEmulatorRawSignals(
    JNIEnv* env, jclass) {
    const dicore::emu::Signals& s = cached_probe();
    return env->NewStringUTF(s.raw);
}

}  // extern "C"
