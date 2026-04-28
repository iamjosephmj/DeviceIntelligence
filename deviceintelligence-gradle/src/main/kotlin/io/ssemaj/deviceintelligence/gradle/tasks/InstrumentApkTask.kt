package io.ssemaj.deviceintelligence.gradle.tasks

import com.android.apksig.ApkSigner
import com.android.build.api.artifact.ArtifactTransformationRequest
import io.ssemaj.deviceintelligence.gradle.internal.ApkHasher
import io.ssemaj.deviceintelligence.gradle.internal.Fingerprint
import io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec
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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * F8 — replaces AGP's signed APK with an instrumented + re-signed APK that
 * embeds `assets/io.ssemaj.deviceintelligence/fingerprint.bin` (the F7 encrypted blob).
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
 * same [io.ssemaj.deviceintelligence.gradle.internal.ApkHasher] / [FingerprintCodec] /
 * [io.ssemaj.deviceintelligence.gradle.internal.CertHasher]-equivalent logic so the bytes baked
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
 *      and append `assets/io.ssemaj.deviceintelligence/fingerprint.bin` (STORED) at the end.
 *      Because pass-1 and pass-2 produce identical bodies for the entries
 *      we care about, the hashes baked from pass 1 remain valid for pass 2.
 *   4. Re-sign pass-2 APK with apksig (v1 + v2 + v3).
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

    /** Per-build XOR key from [GenerateKeyChunksTask]. Build-private. */
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
        val key = keyFile.get().asFile.readBytes()
        require(key.size == KEY_SIZE) {
            "key.bin is the wrong size: ${key.size} (expected $KEY_SIZE)"
        }

        val signing = loadSigningMaterial(
            keystoreFile = keystoreFile.get().asFile,
            configuredType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
            entryPassword = keyPassword.orNull,
        )
        logger.lifecycle(
            "io.ssemaj: instrument: signer leafCertSha256=${signing.certHashes.firstOrNull()}, chainSize=${signing.certs.size}"
        )

        val outDir = outputApkDirectory.get().asFile.apply { mkdirs() }
        transformationRequest.get().submit(this) { builtArtifact ->
            val inputApk = File(builtArtifact.outputFile)
            val outputApk = File(outDir, inputApk.name)
            instrumentOne(inputApk, outputApk, key, signing)
            outputApk
        }
    }

    private fun instrumentOne(
        input: File,
        output: File,
        key: ByteArray,
        signing: SigningMaterial,
    ) {
        // 1. Read input APK entries (decompressed) into memory. Strip META-INF/*
        //    (apksig will regenerate the v1 manifest+signatures during sign()),
        //    and defensively drop any pre-existing fingerprint asset (shouldn't
        //    happen on a clean build, but matters for incremental rebuilds).
        val entries = readInputEntries(input)
        logger.lifecycle(
            "io.ssemaj: instrument ${input.name}: read ${entries.size} entries (META-INF/* stripped)"
        )

        // 2. Pass 1: write APK with all entries, no fingerprint asset.
        val pass1Apk = File(temporaryDir, "${input.nameWithoutExtension}.pass1.apk")
        writeApk(entries, additional = null, output = pass1Apk)

        // 3. Hash pass1 with the same algorithm the runtime + diagnostic
        //    Compute task use (ApkHasher: SHA-256 over compressed body bytes,
        //    skip META-INF/* and the fingerprint asset).
        val ignoredEntries = Fingerprint.DEFAULT_IGNORED_ENTRIES.toSet()
        val ignoredPrefixes = Fingerprint.DEFAULT_IGNORED_ENTRY_PREFIXES
        val hashedEntries = ApkHasher(ignoredEntries, ignoredPrefixes).walk(pass1Apk)
        logger.lifecycle(
            "io.ssemaj: instrument ${input.name}: hashed ${hashedEntries.size} entries (post-repack pass-1)"
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
        )
        val cbo = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val encrypted = ByteArray(cbo.size).also {
            for (i in cbo.indices) {
                it[i] = (cbo[i].toInt() xor key[i % key.size].toInt()).toByte()
            }
        }
        logger.lifecycle(
            "io.ssemaj: instrument ${input.name}: encrypted blob (${cbo.size}B plaintext, ${encrypted.size}B encrypted)"
        )

        // 5. Pass 2: same entries (byte-identical compressed bodies due to
        //    deterministic Deflater) + fingerprint asset (STORED) at the end.
        //    Because the asset is in the ignore set, pass-1's hashes still
        //    describe pass-2's non-ignored entries.
        val pass2Apk = File(temporaryDir, "${input.nameWithoutExtension}.pass2.apk")
        writeApk(
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
            "io.ssemaj: instrument ${input.name} → ${output.relativeTo(project.rootDir)} " +
                "(asset injected, re-signed v1+v2+v3)"
        )
    }

    // ---- ZIP I/O ----------------------------------------------------------

    private data class EntryData(
        val method: Int,
        val time: Long,
        val decompressed: ByteArray,
    )

    private fun readInputEntries(input: File): LinkedHashMap<String, EntryData> {
        val out = LinkedHashMap<String, EntryData>()
        ZipFile(input).use { zf ->
            val it = zf.entries()
            while (it.hasMoreElements()) {
                val e = it.nextElement()
                if (e.isDirectory) continue
                if (e.name.startsWith(META_INF_PREFIX)) continue
                if (e.name == Fingerprint.ASSET_PATH) continue
                val bytes = zf.getInputStream(e).use { it.readBytes() }
                out[e.name] = EntryData(
                    method = if (e.method == ZipEntry.STORED) ZipEntry.STORED else ZipEntry.DEFLATED,
                    time = e.time,
                    decompressed = bytes,
                )
            }
        }
        return out
    }

    private fun writeApk(
        entries: Map<String, EntryData>,
        additional: Pair<String, ByteArray>?,
        output: File,
    ) {
        // Always level 6 (DEFAULT_COMPRESSION) + DEFAULT_STRATEGY. Determinism
        // here is what makes pass-1 and pass-2 produce identical body bytes
        // for non-fingerprint entries.
        //
        // The CountingOutputStream wrapper lets us know the exact byte
        // offset of the next local-file-header before we hand the entry
        // to ZipOutputStream — required for 16 KB page-alignment of
        // STORED .so entries (see writeEntry).
        val counting = CountingOutputStream(FileOutputStream(output))
        ZipOutputStream(counting).use { zip ->
            zip.setLevel(Deflater.DEFAULT_COMPRESSION)
            for ((name, data) in entries) {
                writeEntry(zip, counting, name, data.decompressed, data.method, data.time)
            }
            if (additional != null) {
                val (name, bytes) = additional
                writeEntry(zip, counting, name, bytes, ZipEntry.STORED, time = FIXED_EPOCH_MS)
            }
        }
    }

    private fun writeEntry(
        zip: ZipOutputStream,
        counting: CountingOutputStream,
        name: String,
        data: ByteArray,
        method: Int,
        time: Long,
    ) {
        val entry = ZipEntry(name).apply {
            this.method = method
            this.time = time
            if (method == ZipEntry.STORED) {
                size = data.size.toLong()
                compressedSize = data.size.toLong()
                crc = CRC32().apply { update(data) }.value
            }
        }

        // 16 KB page-align uncompressed shared libraries so Android 15+
        // on 16 KB-page-size devices (Pixel 8a/9, API 35/36 emulators
        // with the 16 KB system image) accepts the .so for direct mmap.
        // The padding goes into the local-file-header's extra field —
        // it does NOT touch the entry body, so the post-instrumentation
        // hash that F10 baked at compute time still matches the runtime
        // ZIP-entry body byte-for-byte.
        //
        // Skipped entirely for DEFLATED entries (those are decompressed
        // before mmap so per-entry alignment doesn't matter) and for
        // anything that isn't a .so (resources.arsc has its own much
        // looser alignment rules).
        if (method == ZipEntry.STORED && name.endsWith(".so")) {
            val nameBytes = name.toByteArray(Charsets.UTF_8)
            val headerSizeBeforeExtra = LOCAL_FILE_HEADER_FIXED_SIZE + nameBytes.size
            val nextDataOffsetWithoutPad = counting.count + headerSizeBeforeExtra
            val rem = (nextDataOffsetWithoutPad % SO_ALIGNMENT).toInt()
            if (rem != 0) {
                // Standard 4-byte extra-field record header (id + size)
                // takes 4 bytes minimum. If the natural padding gap is
                // 1..3 bytes we can't fit the header → bump up to the
                // next page. Worst case wastes 16 KB once per .so;
                // negligible for any real APK.
                var padding = SO_ALIGNMENT - rem
                if (padding < EXTRA_RECORD_HEADER_BYTES) padding += SO_ALIGNMENT
                entry.extra = buildPaddingExtra(padding.toInt())
            }
        }

        zip.putNextEntry(entry)
        zip.write(data)
        zip.closeEntry()
    }

    /**
     * Builds a single well-formed extra-field record of total size
     * [totalBytes]. Uses an unassigned header id (0xCAFE) so well-behaved
     * ZIP readers (Android's PackageManager, apksig, the JDK) skip it
     * cleanly as an unknown record.
     */
    private fun buildPaddingExtra(totalBytes: Int): ByteArray {
        require(totalBytes >= EXTRA_RECORD_HEADER_BYTES) {
            "padding $totalBytes < minimum extra-record header size $EXTRA_RECORD_HEADER_BYTES"
        }
        val out = ByteArray(totalBytes)
        // Header id 0xCAFE, little-endian.
        out[0] = 0xFE.toByte()
        out[1] = 0xCA.toByte()
        // Data size (= totalBytes - 4), little-endian.
        val dataSize = totalBytes - EXTRA_RECORD_HEADER_BYTES
        out[2] = (dataSize and 0xFF).toByte()
        out[3] = ((dataSize ushr 8) and 0xFF).toByte()
        // Body bytes are already zero from ByteArray init.
        return out
    }

    /**
     * Tracks total bytes written through the wrapped stream. Required
     * for computing the byte offset of the next ZIP local-file-header
     * before ZipOutputStream commits it to disk.
     */
    private class CountingOutputStream(out: OutputStream) : FilterOutputStream(out) {
        var count: Long = 0L
            private set

        override fun write(b: Int) {
            out.write(b)
            count++
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            out.write(b, off, len)
            count += len
        }
    }

    // ---- Signing material -------------------------------------------------

    private data class SigningMaterial(
        val privateKey: PrivateKey,
        val certs: List<X509Certificate>,
        val certHashes: List<String>,
    )

    private fun loadSigningMaterial(
        keystoreFile: File,
        configuredType: String?,
        keystorePassword: String,
        alias: String,
        entryPassword: String?,
    ): SigningMaterial {
        require(keystoreFile.isFile) { "keystore not found: $keystoreFile" }

        // Mirror CertHasher: try the configured type first, then PKCS12, then
        // JKS. Older debug keystores are JKS; newer ones default to PKCS12.
        val candidates = buildList {
            if (!configuredType.isNullOrEmpty()) add(configuredType.uppercase())
            add("PKCS12")
            add("JKS")
        }.distinct()
        var ks: KeyStore? = null
        var lastError: Throwable? = null
        for (type in candidates) {
            try {
                val candidate = KeyStore.getInstance(type)
                FileInputStream(keystoreFile).use {
                    candidate.load(it, keystorePassword.toCharArray())
                }
                ks = candidate
                break
            } catch (e: Throwable) {
                lastError = e
            }
        }
        ks ?: throw IllegalStateException(
            "Failed to load keystore $keystoreFile as any of $candidates",
            lastError,
        )

        val pwd = (entryPassword ?: keystorePassword).toCharArray()
        val privateKey = ks.getKey(alias, pwd) as? PrivateKey
            ?: error("alias '$alias' has no PrivateKey entry in $keystoreFile")
        val rawChain = ks.getCertificateChain(alias)
            ?: ks.getCertificate(alias)?.let { arrayOf(it) }
            ?: error("alias '$alias' has no certificate in $keystoreFile")
        val certs = rawChain.map {
            require(it is X509Certificate) { "non-X.509 cert in chain: ${it::class}" }
            it
        }
        val md = MessageDigest.getInstance("SHA-256")
        val certHashes = certs.map { cert ->
            md.reset()
            md.digest(cert.encoded).toHex()
        }
        return SigningMaterial(privateKey, certs, certHashes)
    }

    private fun ByteArray.toHex(): String {
        val hex = "0123456789abcdef".toCharArray()
        val out = CharArray(size * 2)
        for (i in indices) {
            out[i * 2] = hex[(this[i].toInt() shr 4) and 0xF]
            out[i * 2 + 1] = hex[this[i].toInt() and 0xF]
        }
        return String(out)
    }

    private companion object {
        const val KEY_SIZE: Int = 32
        const val META_INF_PREFIX: String = "META-INF/"
        // A constant epoch for the fingerprint asset. The on-disk LFH stores
        // this as DOS time, which doesn't affect ApkHasher (it hashes body
        // bytes, not LFH bytes), but using a constant keeps the asset's LFH
        // stable across builds — useful for diffing.
        const val FIXED_EPOCH_MS: Long = 0L

        // ZIP local-file-header layout: 30 bytes of fixed fields, followed
        // by `name_length` bytes of filename, followed by `extra_length`
        // bytes of extra data, followed by the entry body. The extra
        // field is where 16 KB padding lives.
        const val LOCAL_FILE_HEADER_FIXED_SIZE: Int = 30

        // Each extra-field record carries a 4-byte header (2-byte id +
        // 2-byte data length) followed by `data length` bytes of body.
        const val EXTRA_RECORD_HEADER_BYTES: Int = 4

        // Page size we align uncompressed shared libraries to. Android
        // 15+ on devices booted with 16 KB pages requires this; 4 KB-page
        // devices tolerate the extra padding silently.
        const val SO_ALIGNMENT: Long = 16384L
    }
}
