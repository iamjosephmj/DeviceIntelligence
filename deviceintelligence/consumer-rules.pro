# DeviceIntelligence — consumer R8/ProGuard rules.
#
# The SDK is detection-only: detectors + token crypto live in libdicore.so
# and the decision is made server-side (there is no on-device enforcement or
# kill). The JVM side is a thin suspend facade (tech.thessemaj.deviceintelligence.api.DeviceIntelligence) over
# logic-free up-call shims. So the only things consumers' R8 must NOT strip or
# rename are the JNI surfaces — the class + method names form the JNI symbol /
# up-call targets.

# The bootstrap entry points (provider + AppComponentFactory) are no longer in
# the AAR — the Gradle plugin generates them into the consumer with per-build
# random names (spec 08 Stage A). AGP auto-keeps manifest-referenced components,
# so no -keep is needed here for them.

# The single fixed JNI anchor (spec 08 Stage B). The prebuilt .so binds its
# native methods implicitly by `Java_tech_thessemaj_deviceintelligence_dx_K_<m>`, so the class name + the
# native method names (e/p/c/r/g/s) MUST survive obfuscation. This is the ONLY
# fixed-named JVM surface the AAR exposes.
-keep class tech.thessemaj.deviceintelligence.dx.NativeBridge {
    public static native <methods>;
}

# FrameworkShim is the native up-call surface, reached through a SINGLE obfuscated
# dispatch method `q(int,Object)` (native resolves only `q` by GetStaticMethodID).
# The class name AND every real getter are free to be R8-renamed; we pin just `q`.
# (native no longer FindClass'es the class either — the bootstrap hands its Class
# to the anchor via NativeBridge.s.)
-keepclassmembers class tech.thessemaj.deviceintelligence.internal.FrameworkShim {
    public static java.lang.Object q(int, java.lang.Object);
}

