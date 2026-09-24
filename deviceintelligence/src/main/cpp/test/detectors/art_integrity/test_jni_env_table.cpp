// deviceintelligence/src/main/cpp/test/detectors/art_integrity/test_jni_env_table.cpp
// Host test for Vector C (JNIEnv function-table snapshot + diff). Runs the
// REAL check TU against a fake JNIEnv whose vtable members the test rewrites
// between scans — exactly the late env-hook the detector exists to catch.
// The ProtectedStore pages, /proc/self/maps audit and hash-protect logic all
// run for real on the host; only the JNIEnv shape is faked (shim jni.h).
//
// Pins the watch-list extension of the so-hardening fix wave: the token path
// now rides the jni_cache snapshot, so a late hook must interpose the
// REMAINING live-table call sites — NewStringUTF / GetStringUTFChars /
// CallStaticObjectMethod (the framework shim's static-call marshalling) —
// and those three slots must therefore be watched.
#include "dicore/detectors/art_integrity/checks/jni_env_table.h"

#include <cstdio>
#include <cstring>

static int fails = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); fails++; } } while (0)

int main() {
    using namespace dicore::art_integrity;

    // Fake vtable: a distinct marker per watched member, an env pointing at it.
    JNINativeInterface vt;
    std::memset(&vt, 0, sizeof vt);
    vt.GetMethodID          = (void*)0x1001;
    vt.GetStaticMethodID    = (void*)0x1002;
    vt.RegisterNatives      = (void*)0x1003;
    vt.CallStaticIntMethod  = (void*)0x1004;
    vt.CallObjectMethod     = (void*)0x1005;
    vt.FindClass            = (void*)0x1006;
    vt.NewObject            = (void*)0x1007;
    vt.GetObjectClass       = (void*)0x1008;
    vt.NewStringUTF         = (void*)0x1009;
    vt.GetStringUTFChars    = (void*)0x100a;
    vt.CallStaticObjectMethod = (void*)0x100b;

    JNIEnv env;
    env.functions = &vt;

    JniEnvScanEntry e[16];

    // No snapshot yet: scan is a no-op (fail-open, never a false finding).
    CHECK(scan_jni_env(&env, e, 16) == 0);

    // Capture at "JNI_OnLoad".
    initialize_jni_env(&env);

    // Unmodified table: full watch list reported, nothing drifted.
    const size_t n = scan_jni_env(&env, e, 16);
    CHECK(n == kJniEnvWatched);
    CHECK(n >= 11);  // the fix-wave extension: three string/static-call slots

    static const char* const kExpected[] = {
        "GetMethodID", "GetStaticMethodID", "RegisterNatives",
        "CallStaticIntMethod", "CallObjectMethod", "FindClass",
        "NewObject", "GetObjectClass",
        // --- slots added by the fix wave (late-hook coverage for the
        //     token-path string emissions and the shim's static calls) ---
        "NewStringUTF", "GetStringUTFChars", "CallStaticObjectMethod",
    };
    for (size_t i = 0; i < n && i < 11; ++i) {
        CHECK(e[i].function_name != nullptr);
        if (e[i].function_name)
            CHECK(std::strcmp(e[i].function_name, kExpected[i]) == 0);
        CHECK(!e[i].drifted);
        CHECK(e[i].snapshot_fn == e[i].live_fn);
    }

    // Late hook on a pre-existing slot: still caught.
    vt.RegisterNatives = (void*)0x2003;
    // Late hook on each NEW slot: NewStringUTF (token/enroll emissions)…
    vt.NewStringUTF = (void*)0x2009;
    // …GetStringUTFChars (string marshalling)…
    vt.GetStringUTFChars = (void*)0x200a;
    // …CallStaticObjectMethod (framework-shim static up-call).
    vt.CallStaticObjectMethod = (void*)0x200b;

    CHECK(scan_jni_env(&env, e, 16) == kJniEnvWatched);
    for (size_t i = 0; i < kJniEnvWatched && i < 16; ++i) {
        const bool should_drift =
            (i == 2 || i == 8 || i == 9 || i == 10);  // RegisterNatives + 3 new
        CHECK(e[i].drifted == should_drift);
        if (should_drift) {
            CHECK(e[i].live_fn != e[i].snapshot_fn);
        }
    }

    // scan() re-baselines nothing on intact hash: the drift above must STILL
    // be reported by the next scan (baseline only recaptures on tamper).
    CHECK(scan_jni_env(&env, e, 16) == kJniEnvWatched);
    CHECK(e[8].drifted);   // NewStringUTF still drifted
    CHECK(e[10].drifted);  // CallStaticObjectMethod still drifted
    // Untouched slot stays undrifted across every scan.
    CHECK(!e[5].drifted);

    printf(fails ? "TEST-FAIL\n" : "TEST-OK\n");
    return fails ? 1 : 0;
}
