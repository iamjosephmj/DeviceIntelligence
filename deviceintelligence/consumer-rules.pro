# DeviceIntelligence public API surface kept across consumer R8/ProGuard.

# Top-level entry point. `*;` keeps the const VERSION + methods + the
# auto-generated companion that hosts the @JvmStatic delegators.
-keep class tech.thessemaj.deviceintelligence.DeviceIntelligence { *; }

# Telemetry data classes — backends may reflect over them (e.g. via
# Gson / Moshi when receiving a parsed copy server-side). Keep all
# fields and synthetic accessors.
-keep class tech.thessemaj.deviceintelligence.TelemetryReport { *; }
-keep class tech.thessemaj.deviceintelligence.DeviceContext { *; }
-keep class tech.thessemaj.deviceintelligence.AppContext { *; }
-keep class tech.thessemaj.deviceintelligence.DetectorReport { *; }
-keep class tech.thessemaj.deviceintelligence.Finding { *; }
-keep class tech.thessemaj.deviceintelligence.ReportSummary { *; }
-keep class tech.thessemaj.deviceintelligence.Severity { *; }
-keep class tech.thessemaj.deviceintelligence.DetectorStatus { *; }

# Manifest-merged auto-init provider; Android instantiates it via
# reflection from the merged manifest, so R8 must not strip / rename it.
-keep class tech.thessemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider { *; }

# Native-bound JNI methods must keep their declared signatures so the
# C++ entry points can resolve them at runtime. The class names
# themselves form half of each JNI symbol — they MUST not be renamed.
-keep class tech.thessemaj.deviceintelligence.internal.NativeBridge {
    public static native <methods>;
}
-keepclasseswithmembernames class tech.thessemaj.deviceintelligence.internal.EmulatorProbe {
    native <methods>;
}
-keepclasseswithmembernames class tech.thessemaj.deviceintelligence.internal.ClonerDetector {
    native <methods>;
}

# F9 FingerprintDecoder reflects on the build-time-generated key assembler
# at this fixed FQN. R8 must not rename or strip it (or the assemble()
# entry point), or runtime decryption falls over with KeyMissingException.
# The KeyChunkN.* sub-package classes can be freely renamed: KeyAssembler's
# bytecode references them directly, so R8 rewrites those references in
# lockstep.
-keep class tech.thessemaj.deviceintelligence.gen.internal.KeyAssembler {
    public static tech.thessemaj.deviceintelligence.gen.internal.KeyAssembler INSTANCE;
    public byte[] assemble();
}
