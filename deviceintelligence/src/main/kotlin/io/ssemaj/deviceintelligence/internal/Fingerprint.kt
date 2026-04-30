package io.ssemaj.deviceintelligence.internal

/**
 * Runtime mirror of the build-time `io.ssemaj.deviceintelligence.gradle.internal.Fingerprint`
 * data class. The two share an on-disk binary format ([FingerprintCodec]),
 * so any field added here must be added on the plugin side first (and the
 * format version bumped).
 *
 * Currently `internal`; [ApkIntegrityDetector] surfaces only the
 * relevant fields through the public `TelemetryReport` so downstream
 * consumers never depend on this type directly.
 *
 * The `*ByAbi` maps are v2 additions that back the native-integrity /
 * anti-hooking layer (see `NATIVE_INTEGRITY_DESIGN.md`). They're
 * empty when the blob was produced by a v1 plugin; the runtime
 * silently degrades the corresponding native-integrity checks in
 * that case rather than refusing to start.
 */
internal data class Fingerprint(
    val schemaVersion: Int,
    val builtAtEpochMs: Long,
    val pluginVersion: String,
    val variantName: String,
    val applicationId: String,
    /** SHA-256 hex of each signer certificate (DER) baked at sign time. */
    val signerCertSha256: List<String>,
    /** Map of ZIP entry name -> SHA-256 hex of compressed body bytes. */
    val entries: Map<String, String>,
    /** Exact entry names the runtime must skip when comparing. */
    val ignoredEntries: List<String>,
    /** Entry-name prefixes the runtime must skip when comparing. */
    val ignoredEntryPrefixes: List<String>,
    /** Path prefix the device's installed APK must start with. */
    val expectedSourceDirPrefix: String,
    /** Acceptable installer package names (empty = anyone allowed). */
    val expectedInstallerWhitelist: List<String>,
    /**
     * v2 — list of every `.so` filename packaged under `lib/<abi>/`
     * grouped by ABI. The runtime selects the entry matching
     * `Build.SUPPORTED_ABIS[0]` and feeds it to
     * `NativeBridge.initNativeIntegrity` for the injected-library
     * scanner (Component 4 of the design doc).
     */
    val nativeLibInventoryByAbi: Map<String, List<String>> = emptyMap(),
    /**
     * v2 — whole-file SHA-256 of every `.so`, grouped by ABI. Held
     * for forward compatibility; the runtime currently only consumes
     * filenames.
     */
    val nativeLibHashesByAbi: Map<String, Map<String, String>> = emptyMap(),
    /**
     * v2 — SHA-256 of `libdicore.so`'s ELF `.text` section per ABI.
     * Runtime compares against the live in-memory `.text` to detect
     * pre-load `.so` replacement (Component 3 of the design doc).
     */
    val dicoreTextSha256ByAbi: Map<String, String> = emptyMap(),
) {
    companion object {
        /** Schema currently produced by the plugin. Must match plugin SCHEMA_VERSION. */
        const val SCHEMA_VERSION: Int = 2

        /**
         * Path of the encrypted blob inside the APK as written by F8's
         * [InstrumentApkTask][io.ssemaj.deviceintelligence.gradle.tasks.InstrumentApkTask].
         */
        const val ASSET_PATH: String = "assets/io.ssemaj.deviceintelligence/fingerprint.bin"
    }
}
