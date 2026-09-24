#include "dicore/crypto/sha256.h"
#include "dicore/platform/obf.h"  // DI_OBF_MAX
#include "dicore/jni/jni_anchors.h"

#include <jni.h>

// Minimal JNI bridge. After the rearchitecture the only liveness hook the JVM
// still calls is nativeReady (NativeBridge.isReady()); the old apkEntries /
// apkSignerCertHashes entry points were removed with the Kotlin detectors —
// their zip/sigblock cores are now driven by the native orchestrator
// (apk_verdict_records).

namespace dicore {

DI_OBF_MAX
jboolean JNICALL anchors::nat_liveness(JNIEnv*, jclass) {
    return sha::ensure_initialized() ? JNI_TRUE : JNI_FALSE;
}

} // namespace dicore
