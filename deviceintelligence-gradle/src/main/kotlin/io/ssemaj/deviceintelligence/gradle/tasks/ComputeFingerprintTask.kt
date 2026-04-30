package io.ssemaj.deviceintelligence.gradle.tasks

import com.android.build.api.variant.BuiltArtifactsLoader
import io.ssemaj.deviceintelligence.gradle.internal.ApkHasher
import io.ssemaj.deviceintelligence.gradle.internal.CertHasher
import io.ssemaj.deviceintelligence.gradle.internal.Fingerprint
import io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec
import io.ssemaj.deviceintelligence.gradle.internal.FingerprintJson
import io.ssemaj.deviceintelligence.gradle.internal.NativeLibInventory
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File

/**
 * F6 — emits `fingerprint.json` describing the APK's expected post-build
 * shape (per-entry SHA-256 + signer cert SHA-256). Runs after AGP's
 * package${Variant} produces the signed APK.
 *
 * This task is a pure-JVM task: no Android SDK on its classpath, no native
 * libs, no AGP runtime hacks. It uses [ApkHasher] (mirrors dicore's
 * native ZIP walker byte-for-byte) and [CertHasher] (loads the keystore
 * configured for the variant and hashes the X.509 certs).
 *
 * Output is a build-time intermediate. It is NOT packaged into the APK.
 * Subsequent flags (F7 BakeFingerprint, F8 InstrumentApk) consume it.
 */
@CacheableTask
abstract class ComputeFingerprintTask : DefaultTask() {

    /**
     * AGP's APK output directory for the variant. Contains one or more
     * APK files plus an `output-metadata.json` listing.
     */
    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val apkDirectory: DirectoryProperty

    /** Required to interpret [apkDirectory]'s listing JSON. */
    @get:Internal
    abstract val builtArtifactsLoader: Property<BuiltArtifactsLoader>

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

    /** Currently unused (we only need the keystore password to load the
     *  store), but kept as an input so configuration changes invalidate. */
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
     * Human-readable JSON dump. Intended for diagnostics and debugging only;
     * the binary intermediate ([fingerprintBinaryFile]) is what downstream
     * tasks actually consume.
     */
    @get:OutputFile
    abstract val fingerprintFile: RegularFileProperty

    /**
     * Compact binary intermediate consumed by [io.ssemaj.deviceintelligence.gradle.tasks.BakeFingerprintTask].
     * Format is defined by [FingerprintCodec].
     */
    @get:OutputFile
    abstract val fingerprintBinaryFile: RegularFileProperty

    @TaskAction
    fun compute() {
        val apk = resolveApk()
        logger.lifecycle("io.ssemaj: computing fingerprint for ${apk.name}")

        val ignoredEntries = Fingerprint.DEFAULT_IGNORED_ENTRIES.toSet()
        val ignoredPrefixes = Fingerprint.DEFAULT_IGNORED_ENTRY_PREFIXES

        val hasher = ApkHasher(
            ignoredEntries = ignoredEntries,
            ignoredEntryPrefixes = ignoredPrefixes,
        )
        val entries = hasher.walk(apk)
        logger.lifecycle("io.ssemaj: hashed ${entries.size} entries (skipped META-INF/* + ${Fingerprint.ASSET_PATH})")

        val certs = CertHasher.digestChain(
            keystore = keystoreFile.get().asFile,
            keystoreType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
        )
        logger.lifecycle("io.ssemaj: cert chain size=${certs.size}, leaf=${certs.firstOrNull()}")

        // F19/G0 — compute build-time native-library fingerprint:
        // per-ABI .so inventory, per-file SHA-256, and libdicore.so
        // .text section SHA-256. Runtime uses these for the
        // injected-library check (Component 4) and the .text
        // self-integrity check (Component 3).
        val nativeFp = NativeLibInventory.walkApk(apk)
        logger.lifecycle(
            "io.ssemaj: native libs: abis=${nativeFp.inventoryByAbi.keys}, " +
                "dicoreText=${nativeFp.dicoreTextSha256ByAbi.mapValues { it.value.take(16) + "..." }}"
        )

        val fp = Fingerprint(
            schemaVersion = Fingerprint.SCHEMA_VERSION,
            builtAtEpochMs = System.currentTimeMillis(),
            pluginVersion = pluginVersion.get(),
            variantName = variantName.get(),
            applicationId = applicationId.get(),
            signerCertSha256 = certs,
            entries = entries,
            ignoredEntries = ignoredEntries.toList().sorted(),
            ignoredEntryPrefixes = ignoredPrefixes,
            expectedSourceDirPrefix = "/data/app/",
            expectedInstallerWhitelist = emptyList(),
            nativeLibInventoryByAbi = nativeFp.inventoryByAbi,
            nativeLibHashesByAbi = nativeFp.fileHashesByAbi,
            dicoreTextSha256ByAbi = nativeFp.dicoreTextSha256ByAbi,
        )

        val jsonOut = fingerprintFile.get().asFile
        jsonOut.parentFile.mkdirs()
        jsonOut.writeText(FingerprintJson.encode(fp))
        logger.lifecycle("io.ssemaj: wrote ${jsonOut.relativeTo(project.rootDir)}")

        val cboOut = fingerprintBinaryFile.get().asFile
        cboOut.parentFile.mkdirs()
        cboOut.outputStream().use { FingerprintCodec.encode(fp, it) }
        logger.lifecycle("io.ssemaj: wrote ${cboOut.relativeTo(project.rootDir)} (${cboOut.length()}B)")
    }

    private fun resolveApk(): File {
        val dir = apkDirectory.get()
        val loader = builtArtifactsLoader.get()
        val artifacts = loader.load(dir)
            ?: error("io.ssemaj: AGP listing JSON missing in ${dir.asFile}")
        val outputs = artifacts.elements
        require(outputs.isNotEmpty()) { "io.ssemaj: no APK outputs in ${dir.asFile}" }
        if (outputs.size > 1) {
            logger.warn("io.ssemaj: multiple APK outputs (${outputs.size}); using the first one (${outputs.first().outputFile})")
        }
        return File(outputs.first().outputFile)
    }
}
