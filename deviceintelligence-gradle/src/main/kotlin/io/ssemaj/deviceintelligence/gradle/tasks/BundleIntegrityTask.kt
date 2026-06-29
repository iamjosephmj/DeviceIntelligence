// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleIntegrityTask.kt
package io.ssemaj.deviceintelligence.gradle.tasks

import io.ssemaj.deviceintelligence.gradle.internal.AabSigner
import io.ssemaj.deviceintelligence.gradle.internal.KeystoreSigning
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * App Bundle ("bundle mode") integrity transform over [SingleArtifact.BUNDLE].
 *
 * AGP hands us the just-built, AGP-signed `.aab`; we:
 *   1. Bake the v3 bundle-mode fingerprint blob (decompressed dex/`.so` hashes +
 *      signer allow-set) with [BundleFingerprintBuilder].
 *   2. Repack the AAB with `base/assets/io.ssemaj.deviceintelligence/fingerprint.bin`
 *      injected as a STORED entry, stripping the old `META-INF/` signature and any
 *      pre-existing fingerprint. ONLY file entries are emitted — bundletool rejects
 *      directory entries in a re-packed AAB.
 *   3. JAR-re-sign the result with [AabSigner].
 *
 * Encryption: `XOR(encode(fp), key)` using the per-build `key.bin` from
 * [GenerateKeyChunksTask]. At runtime [FingerprintDecoder] decrypts with the
 * same key recovered via [KeyResolver.assembleKey].
 */
abstract class BundleIntegrityTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val inputAab: RegularFileProperty

    @get:OutputFile
    abstract val outputAab: RegularFileProperty

    /** Per-build XOR key from [GenerateKeyChunksTask]. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val keyFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val keystoreFile: RegularFileProperty

    @get:Input
    @get:Optional
    abstract val keystoreType: Property<String>

    @get:Input
    abstract val keystorePassword: Property<String>

    @get:Input
    abstract val keyAlias: Property<String>

    @get:Input
    @get:Optional
    abstract val keyPassword: Property<String>

    /** Play App Signing cert SHA-256 pins to include in the signer allow-set. */
    @get:Input
    abstract val playSigningCertSha256: SetProperty<String>

    @get:Input
    abstract val variantName: Property<String>

    @get:Input
    abstract val applicationId: Property<String>

    @get:Input
    abstract val pluginVersion: Property<String>

    @TaskAction
    fun run() {
        val key = keyFile.get().asFile.readBytes()
        require(key.size == KEY_SIZE) {
            "key.bin is wrong size: ${key.size}B (expected $KEY_SIZE)"
        }

        val signing = KeystoreSigning.load(
            keystoreFile = keystoreFile.get().asFile,
            configuredType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
            entryPassword = keyPassword.orNull,
        )

        val input = inputAab.get().asFile
        val output = outputAab.get().asFile.apply { parentFile?.mkdirs() }

        val blob = BundleFingerprintBuilder.build(
            aab = input,
            key = key,
            signerCertHashes = signing.certHashes,
            playPins = playSigningCertSha256.getOrElse(emptySet()),
            pluginVersion = pluginVersion.get(),
            variant = variantName.get(),
            appId = applicationId.get(),
        )
        logger.lifecycle(
            "io.ssemaj: bundle-mode fingerprint '${variantName.get()}': " +
                "signerLeaf=${signing.certHashes.firstOrNull()}, " +
                "playPins=${playSigningCertSha256.getOrElse(emptySet()).size}, " +
                "bundleEntries=${blob.size}B"
        )

        injectAsset(input, output, BUNDLE_ASSET_PATH to blob)
        AabSigner.sign(output, signing.privateKey, signing.certs)

        logger.lifecycle(
            "io.ssemaj: bundle-mode integrity → ${output.relativeTo(project.rootDir)} (asset injected, re-signed)"
        )
    }

    /**
     * Copies every file entry from [input] to [output], DROPPING `META-INF/`
     * (old signature), any pre-existing fingerprint asset, and all directory
     * entries (bundletool rejects them in a re-packed AAB); then appends
     * [additional] as a STORED entry.
     */
    private fun injectAsset(input: File, output: File, additional: Pair<String, ByteArray>) {
        if (output.exists()) output.delete()
        ZipFile(input).use { zf ->
            ZipOutputStream(output.outputStream().buffered()).use { zos ->
                val it = zf.entries()
                while (it.hasMoreElements()) {
                    val e = it.nextElement()
                    if (e.isDirectory) continue
                    if (e.name.startsWith("META-INF/")) continue
                    if (e.name == additional.first) continue
                    val bytes = zf.getInputStream(e).use { s -> s.readBytes() }
                    val method = if (e.method == ZipEntry.STORED) ZipEntry.STORED else ZipEntry.DEFLATED
                    writeEntry(zos, e.name, bytes, method, e.time)
                }
                writeEntry(zos, additional.first, additional.second, ZipEntry.STORED, 0L)
            }
        }
    }

    private fun writeEntry(zos: ZipOutputStream, name: String, data: ByteArray, method: Int, time: Long) {
        val entry = ZipEntry(name).apply {
            this.method = method
            this.time = time
            if (method == ZipEntry.STORED) {
                size = data.size.toLong()
                compressedSize = data.size.toLong()
                crc = CRC32().apply { update(data) }.value
            }
        }
        zos.putNextEntry(entry)
        zos.write(data)
        zos.closeEntry()
    }

    private companion object {
        /** Fingerprint asset path inside the AAB's base module. */
        const val BUNDLE_ASSET_PATH = "base/assets/io.ssemaj.deviceintelligence/fingerprint.bin"
        const val KEY_SIZE: Int = 32
    }
}
