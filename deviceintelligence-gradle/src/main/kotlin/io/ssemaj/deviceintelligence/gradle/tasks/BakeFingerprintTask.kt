package io.ssemaj.deviceintelligence.gradle.tasks

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

/**
 * F7 (part 2) — XOR-encrypts the build-time `fingerprint.cbo` produced by
 * [ComputeFingerprintTask] using the per-build key produced by
 * [GenerateKeyChunksTask], emitting `fingerprint.bin`.
 *
 * The output is the runtime-consumable asset that F8 will inject into the
 * APK's `assets/io.ssemaj.deviceintelligence/fingerprint.bin`. F9's runtime decoder reverses
 * this step: read asset → reflect KeyAssembler → XOR-decrypt → parse via
 * the same FingerprintCodec format.
 *
 * Pipeline ordering (the reason we split this task off from key generation):
 *   generateKeyChunks  ─→  kotlin-compile  ─→  package  ─→  compute  ─→  bake
 * If a single task did both, it would need to run BEFORE kotlin-compile (for
 * codegen) and AFTER package (for hashing) — a fundamental cycle.
 */
@CacheableTask
abstract class BakeFingerprintTask : DefaultTask() {

    /** The 32-byte XOR key emitted by [GenerateKeyChunksTask]. Build-private. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val keyFile: RegularFileProperty

    /** Compact binary intermediate emitted by [ComputeFingerprintTask]. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fingerprintBinaryFile: RegularFileProperty

    @get:Input
    abstract val variantName: Property<String>

    /** XOR-encrypted blob, ready to be packaged as an APK asset by [InstrumentApkTask]. */
    @get:OutputFile
    abstract val fingerprintBin: RegularFileProperty

    @TaskAction
    fun bake() {
        val plaintext = fingerprintBinaryFile.get().asFile.readBytes()
        val key = keyFile.get().asFile.readBytes()
        require(plaintext.size >= MIN_PLAINTEXT_SIZE) {
            "fingerprint.cbo is implausibly small (${plaintext.size}B); refusing to bake"
        }
        require(key.size == EXPECTED_KEY_SIZE) {
            "key.bin is the wrong size: ${key.size} (expected $EXPECTED_KEY_SIZE)"
        }

        val ciphertext = ByteArray(plaintext.size).also {
            for (i in plaintext.indices) {
                it[i] = (plaintext[i].toInt() xor key[i % EXPECTED_KEY_SIZE].toInt()).toByte()
            }
        }

        val binOut = fingerprintBin.get().asFile.apply { parentFile.mkdirs() }
        binOut.writeBytes(ciphertext)
        logger.lifecycle(
            "io.ssemaj: wrote ${binOut.relativeTo(project.rootDir)} (${ciphertext.size}B encrypted)"
        )
    }

    private companion object {
        const val EXPECTED_KEY_SIZE: Int = 32
        const val MIN_PLAINTEXT_SIZE: Int = 16
    }
}
