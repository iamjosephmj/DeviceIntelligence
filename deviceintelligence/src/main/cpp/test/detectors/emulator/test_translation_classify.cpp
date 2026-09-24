// Host unit test for the pure INTEL_0056 classifier (translation_classify.cpp).
// Not built by gradle; compiled directly with host c++ (see
// tools/qa/native-unit-tests.sh). The classifier only uses <cstring>/<string>,
// so it builds & runs on the host.
#include "dicore/detectors/emulator/translation/translation_classify.h"

#include <cassert>
#include <cstdio>
#include <cstring>

using namespace dicore;

static const char* kMapsArm64 = ""
        "12c00000-12c94000 r--p 00000000 103:0c 1049    /apex/com.android.art/lib64/libart.so\n"
        "7b4e500000-7b4e520000 r--s 00000000 00:0c 3023   /system/etc/hosts\n";

static const char* kMapsHoudini = ""
        "7a81000000-7a81100000 r-xp 00000000 103:0c 441    /system/lib64/libhoudini.so\n"
        "12c00000-12c94000 r--p 00000000 103:0c 1049    /apex/com.android.art/lib64/libart.so\n";

static const char* kMapsDecoy = ""
        "7a81000000-7a81100000 r-xp 00000000 103:0c 441    /data/local/tmp/mylibhoudinifoo.so\n";

int main() {
    // -- machine_isa_family -------------------------------------------------
    assert(emu::machine_isa_family("aarch64") == 1);
    assert(emu::machine_isa_family("armv8l") == 1);
    assert(emu::machine_isa_family("armv7l") == 1);
    assert(emu::machine_isa_family("x86_64") == 2);
    assert(emu::machine_isa_family("i686") == 2);
    assert(emu::machine_isa_family("i386") == 2);
    assert(emu::machine_isa_family("riscv64") == 0);   // unknown -> fail open
    assert(emu::machine_isa_family("") == 0);
    assert(emu::machine_isa_family(nullptr) == 0);

    // -- clean devices ------------------------------------------------------
    // arm64 process on an arm64 kernel: nothing.
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "aarch64", "0", kMapsArm64);
        assert(!f.affirmative && !f.process_translated && !f.bridge_named && !f.bridge_mapped);
    }
    // 32-bit ARM process on a 64-bit ARM kernel: normal (32-on-64 userland).
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "armv8l", "0", "");
        assert(!f.affirmative);
    }
    // x86_64 process on an x86_64 kernel (an AVD running the native x86_64 ABI).
    {
        emu::TranslationFinding f = emu::classify_translation_for(2, "x86_64", "0", "");
        assert(!f.affirmative);
    }
    // Unknown machine string: fail open even though the bridge prop is odd.
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "riscv64", "0", "");
        assert(!f.affirmative);
    }

    // -- divergence (definitional) -------------------------------------------
    // arm64 process on an x86_64 kernel: LDPlayer/BlueStacks ARM mode.
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "x86_64", "0", "");
        assert(f.affirmative && f.process_translated && !f.bridge_named && !f.bridge_mapped);
        assert(std::strcmp(f.machine, "x86_64") == 0);
    }
    // arm32 process on an i686 kernel.
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "i686", "0", "");
        assert(f.affirmative && f.process_translated);
    }
    // Reverse direction: x86_64 process on an aarch64 kernel.
    {
        emu::TranslationFinding f = emu::classify_translation_for(2, "aarch64", "0", "");
        assert(f.affirmative && f.process_translated);
    }

    // -- bridge prop ----------------------------------------------------------
    // AVD x86_64 image shipping ndk_translation for ARM app compat: process runs
    // native x86_64, but the image names the bridge.
    {
        emu::TranslationFinding f = emu::classify_translation_for(2, "x86_64", "libndk_translation.so", "");
        assert(f.affirmative && f.bridge_named && !f.process_translated);
        assert(std::strcmp(f.bridge, "libndk_translation.so") == 0);
    }
    // Full-path prop value and the no-underscore spelling both count.
    assert(emu::classify_translation_for(1, "aarch64", "/system/lib64/libhoudini.so", "").bridge_named);
    assert(emu::classify_translation_for(1, "aarch64", "libndktranslation.so", "").bridge_named);
    // "0" / empty / an unknown lib name: no finding from the prop alone.
    assert(!emu::classify_translation_for(1, "aarch64", "0", "").bridge_named);
    assert(!emu::classify_translation_for(1, "aarch64", "", "").bridge_named);
    assert(!emu::classify_translation_for(1, "aarch64", "libsomethingelse.so", "").bridge_named);

    // -- maps corroboration ----------------------------------------------------
    // The spoof case: prop hooked to "0", but the bridge is actually mapped —
    // the raw-syscall maps read still fires.
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "aarch64", "0", kMapsHoudini);
        assert(f.affirmative && f.bridge_mapped && !f.bridge_named);
    }
    // Boundary: "mylibhoudinifoo.so" is NOT a libhoudini mapping.
    {
        emu::TranslationFinding f = emu::classify_translation_for(1, "aarch64", "0", kMapsDecoy);
        assert(!f.affirmative);
    }
    // ndk_translation mapped under either spelling.
    assert(emu::classify_translation_for(
               2, "x86_64", "0",
               "7000000000-7000100000 r-xp 00000000 103:0c 441  /system/lib64/libndk_translation.so\n")
           .bridge_mapped);
    assert(emu::classify_translation_for(
               2, "x86_64", "0",
               "7000000000-7000100000 r-xp 00000000 103:0c 441  /system/lib64/libndktranslation.so\n")
           .bridge_mapped);

    printf("all translated_environment pure-classifier tests passed\n");
    return 0;
}
