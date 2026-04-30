package io.ssemaj.deviceintelligence.gradle.internal

/**
 * Build-time data model the plugin emits and the runtime later consumes
 * (after F7 encrypts it and F9 decrypts it back).
 *
 * Schema is versioned so that older blobs decoded by a newer runtime can be
 * detected and handled gracefully. Bump [SCHEMA_VERSION] whenever a field is
 * added, removed, or its semantics change.
 *
 * The `*ByAbi` maps were added in [SCHEMA_VERSION] = 2 to support
 * NATIVE_INTEGRITY_DESIGN.md (Component 1). They're keyed by Android
 * ABI string (`arm64-v8a`, `x86_64`, ...); empty for ABIs that ship
 * no `.so` files. The runtime consults the entry matching
 * `Build.SUPPORTED_ABIS[0]` and ignores the rest.
 */
internal data class Fingerprint(
    val schemaVersion: Int,
    val builtAtEpochMs: Long,
    val pluginVersion: String,
    val variantName: String,
    val applicationId: String,
    /** SHA-256 hex of each signer certificate (DER) found in the keystore. */
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
     * grouped by ABI. Runtime feeds the list for the running ABI to
     * `NativeBridge.initNativeIntegrity` so the in-process loaded-lib
     * scanner can flag injectors.
     */
    val nativeLibInventoryByAbi: Map<String, List<String>> = emptyMap(),
    /**
     * v2 — whole-file SHA-256 of every `.so`, grouped by ABI. Held
     * for forward compatibility (see Component 1 step 3 of the design
     * doc); the runtime currently only reads filenames, but downstream
     * integrity checks may consume this in a later milestone.
     */
    val nativeLibHashesByAbi: Map<String, Map<String, String>> = emptyMap(),
    /**
     * v2 — SHA-256 of `libdicore.so`'s ELF `.text` section per ABI.
     * Runtime compares against the live in-memory `.text` to detect
     * pre-load `.so` replacement (Component 3 / Vector G2).
     */
    val dicoreTextSha256ByAbi: Map<String, String> = emptyMap(),
) {
    companion object {
        /**
         * Bumped from 1 to 2 to add `nativeLibInventoryByAbi`,
         * `nativeLibHashesByAbi`, and `dicoreTextSha256ByAbi`. The
         * runtime decoder accepts both 1 and 2; v1 blobs simply
         * leave the new fields empty.
         */
        const val SCHEMA_VERSION: Int = 2
        const val ASSET_PATH: String = "assets/io.ssemaj.deviceintelligence/fingerprint.bin"
        val DEFAULT_IGNORED_ENTRY_PREFIXES: List<String> = listOf("META-INF/")
        val DEFAULT_IGNORED_ENTRIES: List<String> = listOf(ASSET_PATH)
    }
}
