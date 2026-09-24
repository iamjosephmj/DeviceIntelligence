package tech.thessemaj.deviceintelligence.gradle.internal

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.dsl.ApkSigningConfig
import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.variant.ApplicationVariant
import tech.thessemaj.deviceintelligence.gradle.DeviceIntelligenceExtension
import tech.thessemaj.deviceintelligence.gradle.tasks.BakeFingerprintTask
import tech.thessemaj.deviceintelligence.gradle.tasks.BundleIntegrityTask
import tech.thessemaj.deviceintelligence.gradle.tasks.ComputeFingerprintTask
import tech.thessemaj.deviceintelligence.gradle.tasks.InstrumentApkTask
import org.gradle.api.Project
import org.gradle.kotlin.dsl.register

/**
 * The per-variant fingerprint pipeline wiring for `com.android.application`
 * consumers. Two mutually exclusive modes:
 *
 * - APK mode (default): a Compute → Bake diagnostic pair plus the
 *   [InstrumentApkTask] registered as the `SingleArtifact.APK` transform
 *   (inject + re-sign).
 * - Bundle mode (`deviceintelligence { appBundle.enabled = true }`): the APK transform is
 *   NOT wired; [BundleIntegrityTask] transforms `SingleArtifact.BUNDLE`
 *   instead (bake into the AAB + re-sign).
 *
 * Split out of the plugin class so [tech.thessemaj.deviceintelligence.gradle.DeviceIntelligencePlugin] stays a
 * readable registration skeleton.
 */
internal object FingerprintWiring {

    /**
     * AGP auto-attaches the debug signingConfig to the debug build type.
     * Release / custom build types must wire one explicitly; we do NOT
     * silently fall back to the debug keystore because that would bind
     * the release fingerprint to the wrong cert.
     *
     * Why we read the keystore via the DSL extension and not via the variant
     * API: as of AGP 8.x the `Variant.signingConfig` interface only exposes
     * the `enableV1/V2/V3/V4Signing` flags. The actual `storeFile`,
     * `storePassword`, `keyAlias`, `keyPassword` and `storeType` are DSL-only
     * (`ApkSigningConfig`). We resolve the variant's effective DSL signing
     * config by walking buildType -> signingConfig.
     */
    fun resolveSigningConfig(
        androidExt: ApplicationExtension,
        buildTypeName: String?,
    ): ApkSigningConfig? {
        if (buildTypeName == null) return null
        val buildType = androidExt.buildTypes.findByName(buildTypeName) ?: return null
        return buildType.signingConfig
    }

    /**
     * Bundle mode: bake the fingerprint into the AAB and re-sign it. When this
     * runs, the APK integrity transform is skipped entirely for the variant.
     */
    fun registerBundleIntegrity(
        project: Project,
        ext: DeviceIntelligenceExtension,
        variant: ApplicationVariant,
        signing: ApkSigningConfig,
    ) {
        val cfgStoreFile = signing.storeFile
        val cfgStorePassword = signing.storePassword
        val cfgKeyAlias = signing.keyAlias
        val cfgKeyPassword = signing.keyPassword
        val cfgStoreType = signing.storeType

        val bundleTitle = variant.name.replaceFirstChar { it.uppercase() }
        val bundleTask = project.tasks.register<BundleIntegrityTask>(
            "bundle${bundleTitle}DeviceIntegrity",
        ) {
            group = "deviceintelligence"
            description = "Bakes the bundle-mode device fingerprint into the AAB and re-signs it (variant '${variant.name}')."

            keystoreFile.fileValue(cfgStoreFile)
            keystorePassword.set(cfgStorePassword)
            keyAlias.set(cfgKeyAlias)
            if (cfgKeyPassword != null) keyPassword.set(cfgKeyPassword)
            if (!cfgStoreType.isNullOrBlank()) keystoreType.set(cfgStoreType)
            playSigningCertSha256.set(ext.appBundle.playSigningCertSha256)
            variantName.set(variant.name)
            applicationId.set(variant.applicationId)
            pluginVersion.set(PluginCoordinates.VERSION)
        }
        // Single-file BUNDLE transform: AGP rewires SingleArtifact.BUNDLE
        // to our re-signed output so `bundletool` / Play see the baked AAB.
        variant.artifacts.use(bundleTask)
            .wiredWithFiles(
                BundleIntegrityTask::inputAab,
                BundleIntegrityTask::outputAab,
            )
            .toTransform(SingleArtifact.BUNDLE)

        project.afterEvaluate {
            if (ext.verbose.get()) {
                project.logger.lifecycle("deviceintelligence: registered ${bundleTask.name} (BUNDLE transform)")
            }
        }
    }

    /**
     * APK mode: register Compute (diagnostic), Bake (diagnostic), and the
     * [InstrumentApkTask] `SingleArtifact.APK` transform that does the real
     * work — inject + re-sign.
     */
    fun registerApkPipeline(
        project: Project,
        ext: DeviceIntelligenceExtension,
        variant: ApplicationVariant,
        signing: ApkSigningConfig,
    ) {
        val cfgStoreFile = signing.storeFile
        val cfgStorePassword = signing.storePassword
        val cfgKeyAlias = signing.keyAlias
        val cfgKeyPassword = signing.keyPassword
        val cfgStoreType = signing.storeType

        val variantTitle = variant.name.replaceFirstChar { it.uppercase() }
        val computeTaskName = "compute${variantTitle}DeviceFingerprint"
        val bakeTaskName = "bake${variantTitle}DeviceFingerprint"
        val instrumentTaskName = "instrument${variantTitle}DeviceApk"

        val intermediatesDir = project.layout.buildDirectory
            .dir("intermediates/deviceintelligence/${variant.name}")

        // Spec 04: the fingerprint XOR key is no longer in the dex. The bake
        // step draws a per-build random seed and derives the key via env-KEK
        // (phrase embedded only in libdicore.so), shipping `seed ‖ ciphertext`;
        // the native decoder re-derives the key. So the old key-chunks codegen
        // task (key.bin + KeyChunkN/KeyAssembler) is gone — no generated
        // sources, no kotlin-compile dependency, no key on the consumer dex.

        // Compute task — runs after package${Variant}; reads the signed
        //    APK (which by now contains classes.dex with KeyChunk classes)
        //    and emits fingerprint.json + fingerprint.cbo.
        val computeTask = project.tasks.register<ComputeFingerprintTask>(computeTaskName) {
            group = "deviceintelligence"
            description = "Computes the device fingerprint (APK entry hashes + signer cert hashes) for variant '${variant.name}'."

            apkDirectory.set(variant.artifacts.get(SingleArtifact.APK))
            builtArtifactsLoader.set(variant.artifacts.getBuiltArtifactsLoader())

            keystoreFile.fileValue(cfgStoreFile)
            keystorePassword.set(cfgStorePassword)
            keyAlias.set(cfgKeyAlias)
            if (cfgKeyPassword != null) {
                keyPassword.set(cfgKeyPassword)
            }
            if (!cfgStoreType.isNullOrBlank()) {
                keystoreType.set(cfgStoreType)
            }

            variantName.set(variant.name)
            applicationId.set(variant.applicationId)
            pluginVersion.set(PluginCoordinates.VERSION)
            fingerprintFile.set(intermediatesDir.map { it.file("fingerprint.json") })
            fingerprintBinaryFile.set(intermediatesDir.map { it.file("fingerprint.cbo") })
        }

        // Bake task — env-KEK-encrypts Compute's .cbo into fingerprint.bin
        //    (seed ‖ ciphertext). Standalone diagnostic task; F8's
        //    InstrumentApkTask re-implements bake inline (it cannot consume
        //    Bake's output without forming a cycle through SingleArtifact.APK).
        val bakeTask = project.tasks.register<BakeFingerprintTask>(bakeTaskName) {
            group = "deviceintelligence"
            description = "env-KEK-encrypts the device fingerprint into fingerprint.bin for variant '${variant.name}'. Diagnostic; not consumed by the build pipeline."

            fingerprintBinaryFile.set(computeTask.flatMap { it.fingerprintBinaryFile })
            variantName.set(variant.name)
            fingerprintBin.set(intermediatesDir.map { it.file("fingerprint.bin") })
        }

        // 4) Instrument task — registered as a SingleArtifact.APK transform.
        //    Re-implements compute+bake inline (necessary to avoid a cycle
        //    via SingleArtifact.APK) and re-signs with apksig (v1+v2+v3)
        //    using the same keystore the consumer's signingConfig defines.
        val instrumentTask = project.tasks.register<InstrumentApkTask>(instrumentTaskName) {
            group = "deviceintelligence"
            description = "Injects assets/tech.thessemaj.deviceintelligence/fingerprint.bin into the signed APK and re-signs (variant '${variant.name}')."

            keystoreFile.fileValue(cfgStoreFile)
            keystorePassword.set(cfgStorePassword)
            keyAlias.set(cfgKeyAlias)
            if (cfgKeyPassword != null) {
                keyPassword.set(cfgKeyPassword)
            }
            if (!cfgStoreType.isNullOrBlank()) {
                keystoreType.set(cfgStoreType)
            }

            variantName.set(variant.name)
            applicationId.set(variant.applicationId)
            pluginVersion.set(PluginCoordinates.VERSION)
            minSdkVersion.set(variant.minSdk.apiLevel)
        }

        // Wire the transform so AGP rewires SingleArtifact.APK to our
        // output. Downstream consumers (install, bundle, the diagnostic
        // ComputeFingerprintTask, etc.) then see the instrumented APK.
        val transformationRequest = variant.artifacts.use(instrumentTask)
            .wiredWithDirectories(
                InstrumentApkTask::inputApkDirectory,
                InstrumentApkTask::outputApkDirectory,
            )
            .toTransformMany(SingleArtifact.APK)
        instrumentTask.configure {
            this.transformationRequest.set(transformationRequest)
        }

        project.afterEvaluate {
            if (ext.verbose.get()) {
                project.logger.lifecycle(
                    "deviceintelligence: registered ${computeTask.name} + ${bakeTask.name} + ${instrumentTask.name}"
                )
            }
        }
    }
}
