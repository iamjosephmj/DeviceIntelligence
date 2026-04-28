package io.ssemaj.deviceintelligence.gradle

import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.dsl.ApkSigningConfig
import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import io.ssemaj.deviceintelligence.gradle.tasks.BakeFingerprintTask
import io.ssemaj.deviceintelligence.gradle.tasks.ComputeFingerprintTask
import io.ssemaj.deviceintelligence.gradle.tasks.GenerateKeyChunksTask
import io.ssemaj.deviceintelligence.gradle.tasks.GenerateOptionalManifestTask
import io.ssemaj.deviceintelligence.gradle.tasks.InstrumentApkTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.register

/**
 * Entry point for the `io.ssemaj` Gradle plugin.
 *
 * The plugin only does work when applied alongside an Android plugin:
 *  - For `com.android.application`, it registers a per-variant
 *    [ComputeFingerprintTask] (F6) that emits a build-time `fingerprint.json`
 *    describing the post-package signed APK + its signing identity.
 *  - For `com.android.library`, it currently no-ops; libraries don't ship a
 *    standalone APK and therefore have no signing identity to bind to.
 *
 * Why we read the keystore via the DSL extension and not via the variant
 * API: as of AGP 8.x the `Variant.signingConfig` interface only exposes
 * the `enableV1/V2/V3/V4Signing` flags. The actual `storeFile`,
 * `storePassword`, `keyAlias`, `keyPassword` and `storeType` are DSL-only
 * (`ApkSigningConfig`). We resolve the variant's effective DSL signing
 * config by walking buildType -> signingConfig.
 */
class DeviceIntelligencePlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val ext = project.extensions.create("deviceintelligence", DeviceIntelligenceExtension::class.java).apply {
            verbose.convention(false)
            detectors.convention(emptySet())
            enableVpnDetection.convention(false)
        }

        project.plugins.withId("com.android.application") {
            wireApplication(project, ext)
        }
        project.plugins.withId("com.android.library") {
            wireLibrary(project, ext)
        }
    }

    private fun wireApplication(project: Project, ext: DeviceIntelligenceExtension) {
        val components = project.extensions.findByType(ApplicationAndroidComponentsExtension::class.java)
            ?: error("io.ssemaj: AGP application plugin applied but ApplicationAndroidComponentsExtension is missing")

        val androidExt = project.extensions.findByType(ApplicationExtension::class.java)
            ?: error("io.ssemaj: AGP application plugin applied but ApplicationExtension is missing")

        components.onVariants { variant ->
            // Optional permission injection runs independently of the
            // fingerprint pipeline — it's wired even on variants
            // without a resolvable signingConfig because the consumer
            // can opt into VPN detection regardless of whether the
            // fingerprint binding is configured.
            wireOptionalManifest(project, ext, variant)

            val buildTypeName = variant.buildType
            val signingConfigDsl = resolveSigningConfig(androidExt, buildTypeName)
            if (signingConfigDsl == null) {
                project.logger.warn(
                    "io.ssemaj: variant '${variant.name}' has no resolvable signingConfig; skipping fingerprint task. " +
                        "Configure a signingConfig on buildType '$buildTypeName' to enable DeviceIntelligence build-time integrity binding."
                )
                return@onVariants
            }

            val cfgStoreFile = signingConfigDsl.storeFile
            val cfgStorePassword = signingConfigDsl.storePassword
            val cfgKeyAlias = signingConfigDsl.keyAlias
            val cfgKeyPassword = signingConfigDsl.keyPassword
            val cfgStoreType = signingConfigDsl.storeType

            if (cfgStoreFile == null || cfgStorePassword == null || cfgKeyAlias == null) {
                project.logger.warn(
                    "io.ssemaj: variant '${variant.name}' signingConfig is incomplete (storeFile=$cfgStoreFile, alias=$cfgKeyAlias); skipping fingerprint task."
                )
                return@onVariants
            }

            val variantTitle = variant.name.replaceFirstChar { it.uppercase() }
            val genKeyTaskName = "generate${variantTitle}DeviceIntelligenceKeyChunks"
            val computeTaskName = "compute${variantTitle}DeviceIntelligenceFingerprint"
            val bakeTaskName = "bake${variantTitle}DeviceIntelligenceFingerprint"
            val instrumentTaskName = "instrument${variantTitle}DeviceIntelligenceApk"

            val intermediatesDir = project.layout.buildDirectory
                .dir("intermediates/io.ssemaj/${variant.name}")
            val generatedDir = project.layout.buildDirectory
                .dir("generated/io.ssemaj/${variant.name}/kotlin")

            // 1) Codegen task — runs FIRST, no deps. Produces:
            //    - key.bin (build-private 32B key)
            //    - KeyChunkN.kt + KeyAssembler.kt (consumed by kotlin compile)
            val genKeyTask = project.tasks.register<GenerateKeyChunksTask>(genKeyTaskName) {
                group = "io.ssemaj"
                description = "Generates the per-build XOR key + KeyChunkN/KeyAssembler codegen for variant '${variant.name}'."

                variantName.set(variant.name)
                keyFile.set(intermediatesDir.map { it.file("key.bin") })
                generatedSrcDir.set(generatedDir)
            }

            // Wire the codegen dir into the consumer's variant sources so
            // KeyAssembler / KeyChunkN end up in classes.dex. We register on
            // BOTH `sources.kotlin` and `sources.java` because Kotlin compile
            // consumes both, and at least one combination of AGP/KGP we've
            // hit only honours the dependency wiring on the java source set.
            val kotlinSrc = variant.sources.kotlin
            val javaSrc = variant.sources.java
            project.logger.lifecycle(
                "io.ssemaj: variant '${variant.name}' source-set wiring: kotlin=${kotlinSrc != null}, java=${javaSrc != null}"
            )
            kotlinSrc?.addGeneratedSourceDirectory(genKeyTask, GenerateKeyChunksTask::generatedSrcDir)
            javaSrc?.addGeneratedSourceDirectory(genKeyTask, GenerateKeyChunksTask::generatedSrcDir)
            if (kotlinSrc == null && javaSrc == null) {
                project.logger.warn(
                    "io.ssemaj: variant '${variant.name}' exposes neither kotlin nor java source sets; KeyAssembler will not be on the consumer classpath."
                )
            }

            // Belt-and-braces: if AGP's source-set wiring did not establish
            // a producer-dependency on the kotlin compile (observed on at
            // least one AGP/KGP combination), force it by name. This is
            // safe to do unconditionally — the task is idempotent w.r.t.
            // additional dependsOn relationships.
            val kotlinCompileTaskName = "compile${variantTitle}Kotlin"
            project.tasks.matching { it.name == kotlinCompileTaskName }.configureEach {
                dependsOn(genKeyTask)
            }

            // 2) Compute task — runs after package${Variant}; reads the signed
            //    APK (which by now contains classes.dex with KeyChunk classes)
            //    and emits fingerprint.json + fingerprint.cbo.
            val computeTask = project.tasks.register<ComputeFingerprintTask>(computeTaskName) {
                group = "io.ssemaj"
                description = "Computes the DeviceIntelligence fingerprint (APK entry hashes + signer cert hashes) for variant '${variant.name}'."

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
                pluginVersion.set(PLUGIN_VERSION)
                fingerprintFile.set(intermediatesDir.map { it.file("fingerprint.json") })
                fingerprintBinaryFile.set(intermediatesDir.map { it.file("fingerprint.cbo") })
            }

            // 3) Bake task — combines Generate's key.bin and Compute's .cbo
            //    into the encrypted fingerprint.bin. Standalone diagnostic
            //    task; F8's InstrumentApkTask re-implements bake inline (it
            //    cannot consume Bake's output without forming a cycle through
            //    SingleArtifact.APK — see InstrumentApkTask kdoc).
            val bakeTask = project.tasks.register<BakeFingerprintTask>(bakeTaskName) {
                group = "io.ssemaj"
                description = "XOR-encrypts the DeviceIntelligence fingerprint into fingerprint.bin for variant '${variant.name}'. Diagnostic; not consumed by the build pipeline."

                keyFile.set(genKeyTask.flatMap { it.keyFile })
                fingerprintBinaryFile.set(computeTask.flatMap { it.fingerprintBinaryFile })
                variantName.set(variant.name)
                fingerprintBin.set(intermediatesDir.map { it.file("fingerprint.bin") })
            }

            // 4) Instrument task — registered as a SingleArtifact.APK transform.
            //    Re-implements compute+bake inline (necessary to avoid a cycle
            //    via SingleArtifact.APK) and re-signs with apksig (v1+v2+v3)
            //    using the same keystore the consumer's signingConfig defines.
            val instrumentTask = project.tasks.register<InstrumentApkTask>(instrumentTaskName) {
                group = "io.ssemaj"
                description = "Injects assets/io.ssemaj.deviceintelligence/fingerprint.bin into the signed APK and re-signs (variant '${variant.name}')."

                keyFile.set(genKeyTask.flatMap { it.keyFile })
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
                pluginVersion.set(PLUGIN_VERSION)
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
                if (ext.verbose.getOrElse(false)) {
                    project.logger.lifecycle(
                        "io.ssemaj: registered ${genKeyTask.name} + ${computeTask.name} + ${bakeTask.name} + ${instrumentTask.name}"
                    )
                }
            }
        }
    }

    /**
     * Generate + wire a tiny per-variant manifest fragment carrying
     * any opt-in permissions (currently only `ACCESS_NETWORK_STATE`,
     * gated on `enableVpnDetection = true`).
     *
     * The task is registered unconditionally — it always produces a
     * valid manifest, possibly with zero `<uses-permission>` rows —
     * because AGP captures `addGeneratedManifestFile` wiring at
     * configuration time and we want the `enableVpnDetection`
     * Property to drive only task INPUTS (and thus only the file
     * contents), never the wiring graph itself. This keeps the
     * configuration-cache stable across opt-in toggles.
     */
    private fun wireOptionalManifest(
        project: Project,
        ext: DeviceIntelligenceExtension,
        variant: com.android.build.api.variant.ApplicationVariant,
    ) {
        val variantTitle = variant.name.replaceFirstChar { it.uppercase() }
        val taskName = "generate${variantTitle}DeviceIntelligenceOptionalManifest"
        val outFile = project.layout.buildDirectory
            .file("intermediates/io.ssemaj/${variant.name}/optional-AndroidManifest.xml")

        val task = project.tasks.register<GenerateOptionalManifestTask>(taskName) {
            group = "io.ssemaj"
            description = "Generates the opt-in <uses-permission> manifest fragment for variant '${variant.name}'."

            variantName.set(variant.name)
            needsAccessNetworkState.set(ext.enableVpnDetection)
            outputManifest.set(outFile)
        }

        variant.sources.manifests.addGeneratedManifestFile(task) { it.outputManifest }

        project.afterEvaluate {
            if (ext.verbose.getOrElse(false)) {
                project.logger.lifecycle(
                    "io.ssemaj: registered ${task.name} (vpnDetection=${ext.enableVpnDetection.getOrElse(false)})"
                )
            }
        }
    }

    private fun wireLibrary(project: Project, ext: DeviceIntelligenceExtension) {
        val components = project.extensions.findByType(AndroidComponentsExtension::class.java)
            ?: error("io.ssemaj: AGP library plugin applied but AndroidComponentsExtension is missing")

        components.onVariants { variant ->
            project.afterEvaluate {
                if (ext.verbose.getOrElse(false)) {
                    project.logger.lifecycle(
                        "io.ssemaj: applied to ${project.path} (library), variant=${variant.name} (no fingerprint task — libraries don't ship APKs)"
                    )
                }
            }
        }
    }

    private fun resolveSigningConfig(
        androidExt: ApplicationExtension,
        buildTypeName: String?,
    ): ApkSigningConfig? {
        if (buildTypeName == null) return null
        val buildType = androidExt.buildTypes.findByName(buildTypeName) ?: return null
        // AGP auto-attaches the debug signingConfig to the debug build type.
        // Release / custom build types must wire one explicitly; we do NOT
        // silently fall back to the debug keystore because that would bind
        // the release fingerprint to the wrong cert.
        return buildType.signingConfig
    }

    private companion object {
        const val PLUGIN_VERSION: String = "0.0.0-dev"
    }
}
