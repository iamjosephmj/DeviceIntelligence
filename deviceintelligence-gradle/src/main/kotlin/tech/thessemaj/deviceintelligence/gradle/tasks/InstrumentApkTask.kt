package tech.thessemaj.deviceintelligence.gradle.tasks

import com.android.apksig.ApkSigner
import com.android.build.api.artifact.ArtifactTransformationRequest
import tech.thessemaj.deviceintelligence.gradle.internal.ApkHasher
import tech.thessemaj.deviceintelligence.gradle.internal.ApkRepack
import tech.thessemaj.deviceintelligence.gradle.internal.Fingerprint
import tech.thessemaj.deviceintelligence.gradle.internal.FingerprintCodec
import tech.thessemaj.deviceintelligence.gradle.internal.KeystoreSigning
import tech.thessemaj.deviceintelligence.gradle.internal.NativeLibInventory
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.SecureRandom

/**
 * F8 — replaces AGP's signed APK with an instrumented + re-signed APK that
 * embeds `assets/tech.thessemaj.deviceintelligence/fingerprint.bin` (the F7 encrypted blob).
 *
 * Wired as a [com.android.build.api.artifact.SingleArtifact.APK] transform:
 * AGP hands us the just-signed APK directory as input, and downstream
 * consumers (install, bundle, etc.) see OUR output as the new
 * `SingleArtifact.APK`.
 *
 * # Why we don't just consume [BakeFingerprintTask]'s `fingerprint.bin`
 *
 * The F7 bake task's input is the post-`SingleArtifact.APK` artifact (which,
 * once we register this task as a transform, IS our own output). Wiring
 * Bake → Instrument creates a cycle:
 *
 *     bake → compute → SingleArtifact.APK → Instrument → bake
 *
 * To break it, this task re-implements compute+bake INLINE, calling the
 * same [tech.thessemaj.deviceintelligence.gradle.internal.ApkHasher] / [FingerprintCodec] /
 * [tech.thessemaj.deviceintelligence.gradle.internal.KeystoreSigning] logic so the bytes baked
 * into the APK match what the runtime will recompute. The standalone Compute
 * and Bake tasks are kept as on-demand diagnostics that hash the FINAL
 * (post-instrumentation) APK and produce identical hashes (since they apply
 * the same ignore rules and the fingerprint asset is in the ignore list).
 *
 * # Two-pass repack
 *
 * The fingerprint depends on the entries that end up in the OUTPUT APK, so
 * we can't precompute hashes from the AGP-signed input directly — re-zipping
 * with java.util.zip will re-deflate at our compressor settings (level 6,
 * default strategy), producing different compressed bytes than AGP. We
 * therefore:
 *   1. Pass 1: re-zip all entries (minus the META-INF/ tree) with our
 *      deflater, no fingerprint asset, and SHA-256 the resulting body bytes
 *      via [ApkHasher].
 *   2. Encrypt the resulting [Fingerprint] CBO with the per-build XOR key.
 *   3. Pass 2: re-zip the SAME entries (same input, same deflater settings,
 *      same iteration order — therefore byte-identical compressed bodies)
 *      and append `assets/tech.thessemaj.deviceintelligence/fingerprint.bin` (STORED) at the end.
 *      Because pass-1 and pass-2 produce identical bodies for the entries
 *      we care about, the hashes baked from pass 1 remain valid for pass 2.
 *   4. Re-sign pass-2 APK with apksig (v1 + v2 + v3).
 *
 * (The deterministic ZIP read/write machinery — including 16 KB page
 * alignment of STORED `.so` entries — lives in
 * [tech.thessemaj.deviceintelligence.gradle.internal.ApkRepack].)
 *
 * # Limitations (TODO for a later flag)
 *
 * - Native library alignment is not preserved. ZipOutputStream has no
 *   alignment hooks; if the consumer ships uncompressed `.so` files
 *   (`useLegacyPackaging = false`), the dynamic linker may refuse to mmap
 *   them. The current sample has no native libs, so this is fine for the
 *   F8 demo. A future iteration will switch to AGP's `zipflinger` (or a
 *   manual STORED-entry padding pass) to restore 4-byte alignment.
 * - Stamping is single-signer only.
 */
abstract class InstrumentApkTask : DefaultTask() {

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val inputApkDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputApkDirectory: DirectoryProperty

    @get:Internal
    abstract val transformationRequest: Property<ArtifactTransformationRequest<InstrumentApkTask>>

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

    @get:Input
    abstract val variantName: Property<String>

    @get:Input
    abstract val applicationId: Property<String>

    @get:Input
    abstract val pluginVersion: Property<String>

    /**
     * Consumer's `minSdkVersion`. Required by apksig to decide which signing
     * scheme(s) are mandatory and how to format certificates.
     */
    @get:Input
    abstract val minSdkVersion: Property<Int>

    @TaskAction
    fun instrument() {
        val signing = KeystoreSigning.load(
            keystoreFile = keystoreFile.get().asFile,
            configuredType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
            entryPassword = keyPassword.orNull,
        )
        logger.lifecycle(
            "deviceintelligence: instrument: signer leafCertSha256=${signing.certHashes.firstOrNull()}, chainSize=${signing.certs.size}"
        )

        val outDir = outputApkDirectory.get().asFile.apply { mkdirs() }
        transformationRequest.get().submit(this) { builtArtifact ->
            val inputApk = File(builtArtifact.outputFile)
            val outputApk = File(outDir, inputApk.name)
            instrumentOne(inputApk, outputApk, signing)
            outputApk
        }
    }

    private fun instrumentOne(
        input: File,
        output: File,
        signing: KeystoreSigning.SigningMaterial,
    ) {
        // 1. Read input APK entries (decompressed) into memory. Strip META-INF/*
        //    (apksig will regenerate the v1 manifest+signatures during sign()),
        //    and defensively drop any pre-existing fingerprint asset (shouldn't
        //    happen on a clean build, but matters for incremental rebuilds).
        val entries = ApkRepack.readInputEntries(input)
        logger.lifecycle(
            "deviceintelligence: instrument ${input.name}: read ${entries.size} entries (META-INF/* stripped)"
        )

        // 2. Pass 1: write APK with all entries, no fingerprint asset.
        val pass1Apk = File(temporaryDir, "${input.nameWithoutExtension}.pass1.apk")
        ApkRepack.writeApk(entries, additional = null, output = pass1Apk)

        // 3. Hash pass1 with the same algorithm the runtime + diagnostic
        //    Compute task use (ApkHasher: SHA-256 over compressed body bytes,
        //    skip META-INF/* and the fingerprint asset).
        val ignoredEntries = Fingerprint.DEFAULT_IGNORED_ENTRIES.toSet()
        val ignoredPrefixes = Fingerprint.DEFAULT_IGNORED_ENTRY_PREFIXES
        val hashedEntries = ApkHasher(ignoredEntries, ignoredPrefixes).walk(pass1Apk)
        logger.lifecycle(
            "deviceintelligence: instrument ${input.name}: hashed ${hashedEntries.size} entries (post-repack pass-1)"
        )

        // F19/G0 — compute build-time native-library fingerprint
        // straight from the decompressed entries we already have in
        // memory. Walking the raw bytes here is byte-equivalent to
        // ComputeFingerprintTask's ZipFile-based walk because:
        //   - both look at the same set of lib/<abi>/<file>.so paths
        //   - both hash the entry's decompressed body (whole-file
        //     SHA-256), not the on-disk compressed bytes
        //   - both run the same ElfParser on libdicore.so
        // So a clean rebuild produces identical baselines from either
        // pipeline.
        val nativeFp = NativeLibInventory.walkRawEntries(
            entries.asSequence().map { (name, data) -> name to data.decompressed }
        )
        logger.lifecycle(
            "deviceintelligence: instrument ${input.name}: native libs abis=${nativeFp.inventoryByAbi.keys}, " +
                "dicoreText=${nativeFp.dicoreTextSha256ByAbi.mapValues { it.value.take(16) + "..." }}"
        )

        // 4. Build Fingerprint, encode (CBO), encrypt with per-build key.
        val fp = Fingerprint(
            schemaVersion = Fingerprint.SCHEMA_VERSION,
            builtAtEpochMs = System.currentTimeMillis(),
            pluginVersion = pluginVersion.get(),
            variantName = variantName.get(),
            applicationId = applicationId.get(),
            signerCertSha256 = signing.certHashes,
            entries = hashedEntries,
            ignoredEntries = ignoredEntries.toList().sorted(),
            ignoredEntryPrefixes = ignoredPrefixes,
            expectedSourceDirPrefix = "/data/app/",
            expectedInstallerWhitelist = emptyList(),
            nativeLibInventoryByAbi = nativeFp.inventoryByAbi,
            nativeLibHashesByAbi = nativeFp.fileHashesByAbi,
            dicoreTextSha256ByAbi = nativeFp.dicoreTextSha256ByAbi,
        )
        val cbo = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        // Spec 04 — the XOR key is NOT shipped. We draw a per-build random seed,
        // derive the key via env-KEK (K = SHA256(seed XOR SHA256(phrase))) where
        // the phrase is embedded only in libdicore.so, and prepend the seed to the
        // blob. The native decoder re-derives K from the seed + its embedded phrase
        // (apk_integrity_jni.cpp::fp_derive_key). No key material lives in the dex
        // anymore — this replaces the old KeyChunks/KeyAssembler codegen.
        val seed = ByteArray(KEY_SIZE).also { SecureRandom().nextBytes(it) }
        val key = deriveFpKey(seed)
        val encrypted = ByteArray(KEY_SIZE + cbo.size)
        System.arraycopy(seed, 0, encrypted, 0, KEY_SIZE)
        for (i in cbo.indices) {
            encrypted[KEY_SIZE + i] = (cbo[i].toInt() xor key[i % KEY_SIZE].toInt()).toByte()
        }
        logger.lifecycle(
            "deviceintelligence: instrument ${input.name}: encrypted blob (${cbo.size}B plaintext, " +
                "${encrypted.size}B = ${KEY_SIZE}B seed + ciphertext; key env-KEK-derived, not shipped)"
        )

        // 5. Pass 2: same entries (byte-identical compressed bodies due to
        //    deterministic Deflater) + fingerprint asset (STORED) at the end.
        //    Because the asset is in the ignore set, pass-1's hashes still
        //    describe pass-2's non-ignored entries.
        val pass2Apk = File(temporaryDir, "${input.nameWithoutExtension}.pass2.apk")
        ApkRepack.writeApk(
            entries = entries,
            additional = Fingerprint.ASSET_PATH to encrypted,
            output = pass2Apk,
        )

        // 6. Sign pass2 → final output APK with apksig (v1 + v2 + v3).
        if (output.exists()) output.delete()
        val signerCfg = ApkSigner.SignerConfig.Builder(
            "DeviceIntelligence",
            signing.privateKey,
            signing.certs,
        ).build()
        ApkSigner.Builder(listOf(signerCfg))
            .setInputApk(pass2Apk)
            .setOutputApk(output)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setMinSdkVersion(minSdkVersion.get())
            .build()
            .sign()

        // 7. Cleanup.
        pass1Apk.delete()
        pass2Apk.delete()

        logger.lifecycle(
            "deviceintelligence: instrument ${input.name} → ${output.relativeTo(project.rootDir)} " +
                "(asset injected, re-signed v1+v2+v3)"
        )
    }

    // ---- env-KEK key derivation ------------------------------------------

    /**
     * env-KEK key derivation, delegated to the closed baker (spec 08) so the
     * env-KEK phrase doesn't ship in the open-source plugin. Byte-identical to the
     * native `apk_integrity_jni.cpp::fp_derive_key`: K = SHA256(seed XOR SHA256(phrase)).
     * The phrase now lives only in libdicore.so + the closed baker JAR; the seed is
     * per-build random and shipped in the blob, so the dex carries no key material.
     */
    private fun deriveFpKey(seed: ByteArray): ByteArray =
        tech.thessemaj.deviceintelligence.baker.DeviceIntelligenceBaker.fpKey(seed)

    private companion object {
        const val KEY_SIZE: Int = 32
    }
}
