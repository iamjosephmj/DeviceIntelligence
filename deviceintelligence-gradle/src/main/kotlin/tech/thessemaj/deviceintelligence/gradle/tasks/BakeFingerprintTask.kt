package tech.thessemaj.deviceintelligence.gradle.tasks

import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Diagnostic — env-KEK-encrypts the build-time `fingerprint.cbo` into
 * `fingerprint.bin` (`seed(32) ‖ ciphertext`). The real shipped blob is produced
 * inline by [InstrumentApkTask] (this task is not consumed by the pipeline; see
 * its kdoc for why bake must be inlined to avoid a SingleArtifact.APK cycle).
 *
 * Spec 04: the XOR key is NOT shipped. A per-build random seed is drawn and the
 * key is derived via env-KEK — `K = SHA256(seed XOR SHA256(phrase))` — where the
 * phrase is embedded only in `libdicore.so` (and mirrored here). The native
 * decoder (`apk_integrity_jni.cpp::fp_derive_key`) re-derives `K` from the seed +
 * its embedded phrase, so no key material lives in the dex. This replaced the old
 * KeyChunks/KeyAssembler codegen.
 */
@CacheableTask
abstract class BakeFingerprintTask : DefaultTask() {

    /** Compact binary intermediate emitted by [ComputeFingerprintTask]. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fingerprintBinaryFile: RegularFileProperty

    @get:Input
    abstract val variantName: Property<String>

    /** env-KEK-encrypted blob (seed ‖ ciphertext), packaged as an APK asset. */
    @get:OutputFile
    abstract val fingerprintBin: RegularFileProperty

    @TaskAction
    fun bake() {
        val plaintext = fingerprintBinaryFile.get().asFile.readBytes()
        require(plaintext.size >= MIN_PLAINTEXT_SIZE) {
            "fingerprint.cbo is implausibly small (${plaintext.size}B); refusing to bake"
        }

        val seed = ByteArray(KEY_SIZE).also { SecureRandom().nextBytes(it) }
        val key = deriveFpKey(seed)
        val out = ByteArray(KEY_SIZE + plaintext.size)
        System.arraycopy(seed, 0, out, 0, KEY_SIZE)
        for (i in plaintext.indices) {
            out[KEY_SIZE + i] = (plaintext[i].toInt() xor key[i % KEY_SIZE].toInt()).toByte()
        }

        val binOut = fingerprintBin.get().asFile.apply { parentFile.mkdirs() }
        binOut.writeBytes(out)
        logger.lifecycle(
            "deviceintelligence: wrote ${binOut.relativeTo(project.rootDir)} " +
                "(${out.size}B = ${KEY_SIZE}B seed + ciphertext; key env-KEK-derived, not shipped)"
        )
    }

    /** Byte-identical to apk_integrity_jni.cpp::fp_derive_key + InstrumentApkTask. */
    private fun deriveFpKey(seed: ByteArray): ByteArray {
        val mix = MessageDigest.getInstance("SHA-256")
            .digest(FP_KEY_PHRASE.toByteArray(Charsets.US_ASCII))
        val eff = ByteArray(KEY_SIZE) { (seed[it].toInt() xor mix[it].toInt()).toByte() }
        return MessageDigest.getInstance("SHA-256").digest(eff)
    }

    private companion object {
        const val KEY_SIZE: Int = 32
        const val MIN_PLAINTEXT_SIZE: Int = 16
        const val FP_KEY_PHRASE: String = "dicore-fpkey-mix-v1"
    }
}
