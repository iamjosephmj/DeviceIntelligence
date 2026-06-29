// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilder.kt
package io.ssemaj.deviceintelligence.gradle.tasks

import io.ssemaj.deviceintelligence.gradle.internal.AabHasher
import io.ssemaj.deviceintelligence.gradle.internal.Fingerprint
import io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec
import io.ssemaj.deviceintelligence.gradle.internal.NativeLibInventory
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipFile

/**
 * Pure builder for the bundle-mode fingerprint blob baked into an AAB's base
 * assets. Kept free of AGP/Gradle types so it can be unit-tested directly.
 *
 * Encryption: `XOR(encode(fp), key)` — the same scheme APK mode uses
 * ([InstrumentApkTask] reads `key.bin` from [GenerateKeyChunksTask] and XORs).
 * At runtime [KeyResolver.assembleKey] returns the same key; [FingerprintDecoder]
 * XOR-decrypts and passes to [FingerprintCodec.decode].
 *
 * DI divergence from RASP: RASP uses `DiBaker.fpKey(seed)` producing a
 * `seed ‖ ciphertext` envelope. DI has no DiBaker — the caller passes `key`
 * (the 32-byte `key.bin`) and the output is simply `XOR(cbo, key)`.
 */
internal object BundleFingerprintBuilder {

    /**
     * Build the encrypted bundle-mode fingerprint blob for [aab].
     *
     * @param aab The `.aab` file (AGP-built, before injection).
     * @param key The 32-byte per-build XOR key from `GenerateKeyChunksTask.keyFile`.
     * @param signerCertHashes SHA-256 hex hashes of the upload-key cert(s).
     * @param playPins Play App Signing cert SHA-256(s) declared in `appBundle.playSigningCertSha256`.
     * @param pluginVersion Plugin version string baked into the fingerprint.
     * @param variant AGP variant name (e.g. `"release"`).
     * @param appId Application ID.
     * @return `XOR(FingerprintCodec.encode(fp), key)` as a byte array.
     */
    fun build(
        aab: File,
        key: ByteArray,
        signerCertHashes: List<String>,
        playPins: Collection<String>,
        pluginVersion: String,
        variant: String,
        appId: String,
    ): ByteArray {
        require(key.size == 32) { "key must be 32 bytes, got ${key.size}" }
        val bundleEntries = AabHasher.bundleEntryHashes(aab)
        val nativeFp = NativeLibInventory.walkRawEntries(aabBaseLibEntries(aab))

        // Membership allow-set: upload-key cert(s) ∪ Play App Signing pins, de-duped.
        val signerAllowSet = (signerCertHashes + playPins).distinct()

        val fp = Fingerprint(
            schemaVersion = Fingerprint.SCHEMA_VERSION,
            builtAtEpochMs = System.currentTimeMillis(),
            pluginVersion = pluginVersion,
            variantName = variant,
            applicationId = appId,
            signerCertSha256 = signerAllowSet,
            // Bundle mode does not bake compressed-byte entry hashes — Play re-deflates.
            entries = emptyMap(),
            ignoredEntries = emptyList(),
            ignoredEntryPrefixes = emptyList(),
            expectedSourceDirPrefix = "/data/app/",
            expectedInstallerWhitelist = emptyList(),
            nativeLibInventoryByAbi = nativeFp.inventoryByAbi,
            nativeLibHashesByAbi = nativeFp.fileHashesByAbi,
            dicoreTextSha256ByAbi = nativeFp.dicoreTextSha256ByAbi,
            bundleMode = true,
            bundleEntryHashes = bundleEntries,
        )

        val cbo = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        return ByteArray(cbo.size).also { out ->
            for (i in cbo.indices) {
                out[i] = (cbo[i].toInt() xor key[i % key.size].toInt()).toByte()
            }
        }
    }

    /**
     * Stream the AAB's `base/lib/<abi>/<file>.so` entries as
     * `lib/<abi>/<file>.so` (APK-relative) path + decompressed body pairs,
     * so [NativeLibInventory.walkRawEntries] computes the ELF `.text`
     * baseline identically to APK mode.
     */
    private fun aabBaseLibEntries(aab: File): Sequence<Pair<String, ByteArray>> {
        val list = ArrayList<Pair<String, ByteArray>>()
        ZipFile(aab).use { zf ->
            val it = zf.entries()
            while (it.hasMoreElements()) {
                val e = it.nextElement()
                if (e.isDirectory) continue
                if (!e.name.startsWith("base/lib/") || !e.name.endsWith(".so")) continue
                val apkPath = e.name.removePrefix("base/") // lib/<abi>/<file>.so
                val bytes = zf.getInputStream(e).use { s -> s.readBytes() }
                list += apkPath to bytes
            }
        }
        return list.asSequence()
    }
}
