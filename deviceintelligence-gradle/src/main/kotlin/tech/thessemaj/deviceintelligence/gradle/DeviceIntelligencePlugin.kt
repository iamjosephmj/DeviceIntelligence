package tech.thessemaj.deviceintelligence.gradle

import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.variant.AndroidComponentsExtension
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import tech.thessemaj.deviceintelligence.gradle.internal.BootstrapWiring
import tech.thessemaj.deviceintelligence.gradle.internal.FingerprintWiring
import tech.thessemaj.deviceintelligence.gradle.internal.RuntimeDependencyWiring
import tech.thessemaj.deviceintelligence.gradle.internal.SignerBaselineGate
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Entry point for the `deviceintelligence` Gradle plugin.
 *
 * The plugin only does work when applied alongside an Android plugin:
 *  - For `com.android.application`, it registers a per-variant
 *    [ComputeFingerprintTask] (F6) that emits a build-time `fingerprint.json`
 *    describing the post-package signed APK + its signing identity.
 *  - For `com.android.library`, it currently no-ops; libraries don't ship a
 *    standalone APK and therefore have no signing identity to bind to.
 *
 * This class is the registration skeleton only; the actual wiring lives in
 * [tech.thessemaj.deviceintelligence.gradle.internal.RuntimeDependencyWiring] (the auto-added
 * runtime AAR), [tech.thessemaj.deviceintelligence.gradle.internal.BootstrapWiring] (the
 * randomized bootstrap generator) and
 * [tech.thessemaj.deviceintelligence.gradle.internal.FingerprintWiring] (the APK / AAB
 * fingerprint pipeline).
 */
class DeviceIntelligencePlugin : Plugin<Project> {
    override fun apply(project: Project) {
        // Conventions are the ONE place a default is written. Every read below is a
        // plain get(): a getOrElse at the call site restates the default, and they
        // drift — appBundle.enabled had a default at its only call site and no
        // convention at all, so wiring it to a task input would have had no value.
        val ext = project.extensions.create("deviceintelligence", DeviceIntelligenceExtension::class.java).apply {
            verbose.convention(false)
            disableAutoRuntimeDependency.convention(false)
            appBundle.enabled.convention(false)
        }

        RuntimeDependencyWiring.wire(project, ext)

        project.plugins.withId("com.android.application") {
            wireApplication(project, ext)
        }
        project.plugins.withId("com.android.library") {
            wireLibrary(project, ext)
        }
    }

    private fun wireApplication(project: Project, ext: DeviceIntelligenceExtension) {
        val components = project.extensions.findByType(ApplicationAndroidComponentsExtension::class.java)
            ?: error("deviceintelligence: AGP application plugin applied but ApplicationAndroidComponentsExtension is missing")

        val androidExt = project.extensions.findByType(ApplicationExtension::class.java)
            ?: error("deviceintelligence: AGP application plugin applied but ApplicationExtension is missing")

        components.onVariants { variant ->
            // Spec 08 (Stage A): generate the bootstrap entry points (provider +
            // app-component-factory) INTO this consumer with per-build random
            // names + a random provider authority, instead of shipping the
            // telltale named classes in the AAR.
            BootstrapWiring.wire(project, ext, variant)

            val buildTypeName = variant.buildType

            if (buildTypeName != "debug") {
                when (val d = SignerBaselineGate.decide(
                    project.findProperty("deviceintelligence.expectedSigner") as String?,
                    project.findProperty("deviceintelligence.signerBaseline.skip") as String?,
                )) {
                    is SignerBaselineGate.Fail -> throw GradleException("deviceintelligence: ${d.reason}")
                    is SignerBaselineGate.AllowDeferred -> project.logger.lifecycle("deviceintelligence: ${d.reason}")
                    SignerBaselineGate.Allow -> Unit
                }
            }

            val signingConfigDsl = FingerprintWiring.resolveSigningConfig(androidExt, buildTypeName)
            if (signingConfigDsl == null) {
                project.logger.warn(
                    "deviceintelligence: variant '${variant.name}' has no resolvable signingConfig; skipping fingerprint task. " +
                        "Configure a signingConfig on buildType '$buildTypeName' to enable DeviceIntelligence build-time integrity binding."
                )
                return@onVariants
            }

            val cfgStoreFile = signingConfigDsl.storeFile
            val cfgStorePassword = signingConfigDsl.storePassword
            val cfgKeyAlias = signingConfigDsl.keyAlias

            if (cfgStoreFile == null || cfgStorePassword == null || cfgKeyAlias == null) {
                project.logger.warn(
                    "deviceintelligence: variant '${variant.name}' signingConfig is incomplete (storeFile=$cfgStoreFile, alias=$cfgKeyAlias); skipping fingerprint task."
                )
                return@onVariants
            }

            // App Bundle ("bundle mode") and APK instrumentation are mutually
            // exclusive per variant. When bundle mode is on, the APK integrity
            // transform is NOT wired; bundle-mode integrity (baked into the
            // AAB + AAB re-sign) is registered instead.
            if (ext.appBundle.enabled.get()) {
                project.logger.lifecycle(
                    "deviceintelligence: appBundle.enabled=true — APK integrity transform skipped for variant " +
                        "'${variant.name}'; bundle-mode integrity applies"
                )
                FingerprintWiring.registerBundleIntegrity(project, ext, variant, signingConfigDsl)
                return@onVariants
            }

            FingerprintWiring.registerApkPipeline(project, ext, variant, signingConfigDsl)
        }
    }

    private fun wireLibrary(project: Project, ext: DeviceIntelligenceExtension) {
        val components = project.extensions.findByType(AndroidComponentsExtension::class.java)
            ?: error("deviceintelligence: AGP library plugin applied but AndroidComponentsExtension is missing")

        components.onVariants { variant ->
            project.afterEvaluate {
                if (ext.verbose.get()) {
                    project.logger.lifecycle(
                        "deviceintelligence: applied to ${project.path} (library), variant=${variant.name} (no fingerprint task — libraries don't ship APKs)"
                    )
                }
            }
        }
    }
}
