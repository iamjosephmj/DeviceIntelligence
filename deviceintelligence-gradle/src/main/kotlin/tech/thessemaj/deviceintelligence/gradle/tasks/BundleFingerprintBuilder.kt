package tech.thessemaj.deviceintelligence.gradle.tasks

import tech.thessemaj.deviceintelligence.baker.DeviceIntelligenceBaker
import tech.thessemaj.deviceintelligence.gradle.internal.AabHasher
import tech.thessemaj.deviceintelligence.gradle.internal.Fingerprint
import tech.thessemaj.deviceintelligence.gradle.internal.FingerprintCodec
import tech.thessemaj.deviceintelligence.gradle.internal.NativeLibInventory
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom
import java.util.zip.ZipFile

/**
 * Pure builder for the bundle-mode fingerprint blob baked into an AAB's base
 * assets. Kept free of any AGP/Gradle types so it can be unit-tested directly.
 *
 * The output is the same `seed ‖ ciphertext` envelope APK mode ships (see
 * InstrumentApkTask): a per-build random 32-byte seed, then the v3
 * [FingerprintCodec] blob XOR-encrypted with the env-KEK-derived key
 * ([DeviceIntelligenceBaker.fpKey]). The native decoder re-derives the key from the seed.
 */
object BundleFingerprintBuilder {

    /** Builds the encrypted bundle-mode fingerprint blob for [aab]. */
    fun build(
        aab: File,
        signerCertHashes: List<String>,
        playPins: Collection<String>,
        pluginVersion: String,
        variant: String,
        appId: String,
    ): ByteArray {
        val bundleEntries = AabHasher.bundleEntryHashes(aab)
        val nativeFp = NativeLibInventory.walkRawEntries(aabBaseLibEntries(aab))
        // Membership allow-set: the keystore signer(s) plus any Play App Signing
        // pins the consumer declared. De-duplicated, order-stable.
        val signer = (signerCertHashes + playPins).distinct()

        val fp = Fingerprint(
            schemaVersion = Fingerprint.SCHEMA_VERSION,
            builtAtEpochMs = System.currentTimeMillis(),
            pluginVersion = pluginVersion,
            variantName = variant,
            applicationId = appId,
            signerCertSha256 = signer,
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
        val seed = ByteArray(KEY_SIZE).also { SecureRandom().nextBytes(it) }
        val key = DeviceIntelligenceBaker.fpKey(seed)
        val out = ByteArray(KEY_SIZE + cbo.size)
        System.arraycopy(seed, 0, out, 0, KEY_SIZE)
        for (i in cbo.indices) {
            out[KEY_SIZE + i] = (cbo[i].toInt() xor key[i % KEY_SIZE].toInt()).toByte()
        }
        return out
    }

    /**
     * Streams the AAB's `base/lib/<abi>/<file>.so` entries as the
     * `lib/<abi>/<file>.so` (APK-relative) paths + decompressed bodies that
     * [NativeLibInventory.walkRawEntries] expects — so the ELF `.text` / inventory
     * baseline is computed identically to APK mode.
     */
    private fun aabBaseLibEntries(aab: File): Sequence<Pair<String, ByteArray>> {
        val out = ArrayList<Pair<String, ByteArray>>()
        ZipFile(aab).use { zf ->
            val it = zf.entries()
            while (it.hasMoreElements()) {
                val e = it.nextElement()
                if (e.isDirectory) continue
                if (!e.name.startsWith("base/lib/") || !e.name.endsWith(".so")) continue
                val apkPath = e.name.removePrefix("base/") // lib/<abi>/<file>.so
                val bytes = zf.getInputStream(e).use { s -> s.readBytes() }
                out += apkPath to bytes
            }
        }
        return out.asSequence()
    }

    private const val KEY_SIZE: Int = 32
}
