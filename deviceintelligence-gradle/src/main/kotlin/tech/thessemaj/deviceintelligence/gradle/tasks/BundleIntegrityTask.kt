package tech.thessemaj.deviceintelligence.gradle.tasks

import tech.thessemaj.deviceintelligence.gradle.internal.AabSigner
import tech.thessemaj.deviceintelligence.gradle.internal.Fingerprint
import tech.thessemaj.deviceintelligence.gradle.internal.KeystoreSigning
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
 * App Bundle ("bundle mode") integrity transform over [com.android.build.api.artifact.SingleArtifact.BUNDLE].
 *
 * AGP hands us the just-built, AGP-signed `.aab`; we:
 *   1. bake the v3 bundle-mode fingerprint blob (decompressed dex/`.so` hashes +
 *      signer allow-set) with [BundleFingerprintBuilder],
 *   2. repack the AAB with `base/assets/tech.thessemaj.deviceintelligence/fingerprint.bin`
 *      injected (STORED), stripping the old `META-INF/` signature and emitting
 *      ONLY file entries (the Task 0 spike: bundletool rejects directory entries),
 *   3. JAR-re-sign the result with [AabSigner].
 *
 * Downstream consumers (the `bundle*` outputs, `bundletool`) then see OUR AAB.
 */
abstract class BundleIntegrityTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val inputAab: RegularFileProperty

    @get:OutputFile
    abstract val outputAab: RegularFileProperty

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

    /** Play App Signing cert SHA-256 pins to add to the membership allow-set. */
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
            signerCertHashes = signing.certHashes,
            playPins = playSigningCertSha256.getOrElse(emptySet()),
            pluginVersion = pluginVersion.get(),
            variant = variantName.get(),
            appId = applicationId.get(),
        )
        logger.lifecycle(
            "deviceintelligence: bundle-mode fingerprint for '${variantName.get()}': " +
                "signer leaf=${signing.certHashes.firstOrNull()}, " +
                "playPins=${playSigningCertSha256.getOrElse(emptySet()).size}, blob=${blob.size}B"
        )

        injectAsset(input, output, BUNDLE_ASSET_PATH to blob)
        AabSigner.sign(output, signing.privateKey, signing.certs)

        logger.lifecycle(
            "deviceintelligence: bundle-mode integrity → ${output.relativeTo(project.rootDir)} (asset injected, AAB re-signed v1)"
        )
    }

    /**
     * Copies every file entry from [input] to [output] (decompressed bodies,
     * original method preserved), DROPPING `META-INF/` (the old signature),
     * any pre-existing fingerprint asset, and all directory entries; then
     * appends [additional] as a STORED entry. No directory entries are emitted —
     * bundletool rejects them on a re-packed AAB.
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
        val BUNDLE_ASSET_PATH: String = "base/" + Fingerprint.ASSET_PATH
    }
}
