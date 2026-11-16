// Host unit test for the pure map-label classifiers in maps_parse.
//
// These two predicates decide whether an EXECUTABLE mapping is legitimate. Get
// either wrong in the permissive direction and the detector goes blind; get it
// wrong in the strict direction and every clean device of some OEM/API
// combination reports injected code. Both have happened, so the labels below are
// real strings observed in the field, not invented ones.
#include "dicore/detectors/environment/maps/maps_parse.h"

#include <cassert>
#include <cstdio>

int main() {
    using namespace dicore::env;

    // --- ART JIT code cache: legitimate on every device, must never be foreign ---

    // Android 11 (Samsung): the JIT cache is ashmem-backed and the zygote cache
    // carries a `_<pid>_<seq>` suffix. Reported as a HIGH false positive from the
    // field. Note "jit-zygote-cache" does NOT contain the substring "jit-cache".
    assert(jit_anon("/dev/ashmem/jit-zygote-cache_540_540") == true);
    assert(jit_anon("/dev/ashmem/jit-cache_540_540") == true);

    // memfd-backed on modern ART.
    assert(jit_anon("/memfd:jit-cache (deleted)") == true);
    assert(jit_anon("/memfd:jit-zygote-cache (deleted)") == true);

    // Private anonymous RWX on older builds, and the HyperOS rename.
    assert(jit_anon("[anon:dalvik-jit-code-cache]") == true);
    assert(jit_anon("[anon_shmem:dalvik-jit-code-cache]") == true);
    assert(jit_anon("[anon:jit-cache]") == true);

    // Future / OEM renames inside the same containers. These are the cases an
    // exact-name list cannot cover, and each one would be a HIGH on every clean
    // device of that build.
    assert(jit_anon("/dev/ashmem/jit-boot-cache_1_1") == true);
    assert(jit_anon("/memfd:jit-shared-cache (deleted)") == true);
    assert(jit_anon("/dev/ashmem/dalvik-jit-code-cache_540_2") == true);

    // --- and the things that must STAY visible ---

    // Injected code living in the SAME containers, from the red-team corpus.
    // Neither names a JIT region, so neither is exempted.
    assert(jit_anon("/memfd:frida-agent-64.so") == false);
    assert(jit_anon("/memfd:zygisk-module") == false);
    assert(jit_anon("/dev/ashmem/frida") == false);

    // "jit" OUTSIDE a JIT container must never exempt anything — a dropped
    // library cannot buy immunity by choosing its filename.
    assert(jit_anon("/data/local/tmp/libjit.so") == false);
    // A file-backed path only wins the exemption from inside a JIT container.
    assert(jit_anon("/data/local/tmp/jit-cache-hook.so") == false);
    assert(jit_anon("/data/app/~~x/com.y/lib/arm64/libdalvik-jit.so") == false);
    assert(jit_anon("/sdcard/art-jit") == false);

    // The mapping behind a ByteBuffer-loaded dex. A wide "dalvik" match once
    // swallowed this, which is precisely what an injected in-memory dex leaves.
    assert(jit_anon("[anon:dalvik-DEX data]") == false);
    assert(jit_anon("[anon:dalvik-main space]") == false);
    // A hostile mapping must not be exempted by living under /dev/ashmem.
    assert(jit_anon("/dev/ashmem/injected") == false);
    assert(jit_anon("/data/local/tmp/libhook.so") == false);
    assert(jit_anon("") == false);

    // --- executable-code roots ---
    assert(is_legit_code_root("/system/lib64/libc.so") == true);
    assert(is_legit_code_root("/apex/com.android.art/lib64/libart.so") == true);
    assert(is_legit_code_root("/data/app/~~ab==/com.x-1/lib/arm64/libfoo.so") == true);
    assert(is_legit_code_root("[vdso]") == true);
    // The JIT cache is NOT a code root — jit_anon is what exempts it, so that the
    // exemption stays narrow and auditable in one place.
    assert(is_legit_code_root("/dev/ashmem/jit-zygote-cache_540_540") == false);
    assert(is_legit_code_root("/data/local/tmp/libhook.so") == false);
    assert(is_legit_code_root("/data/adb/modules/x/lib.so") == false);

    printf("all maps classifier tests passed\n");
    return 0;
}
