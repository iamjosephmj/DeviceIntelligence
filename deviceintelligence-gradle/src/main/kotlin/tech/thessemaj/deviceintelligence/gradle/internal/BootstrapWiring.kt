package tech.thessemaj.deviceintelligence.gradle.internal

import com.android.build.api.variant.ApplicationVariant
import tech.thessemaj.deviceintelligence.gradle.DeviceIntelligenceExtension
import tech.thessemaj.deviceintelligence.gradle.tasks.GenerateBootstrapTask
import org.gradle.api.Project
import org.gradle.kotlin.dsl.register

/**
 * Spec 08 (Stage A) — the per-build bootstrap entry-point generator.
 *
 * Registers a task that generates the randomized bootstrap (provider +
 * app-component-factory) INTO the consumer, with per-build random names + a
 * random provider authority, instead of shipping the telltale named classes
 * in the AAR. Names are rolled once here (per configuration) so the sources
 * and the manifest agree; a config-cache miss (clean build, e.g. release)
 * re-rolls.
 *
 * Runs independently of the fingerprint pipeline — it is wired even on
 * variants without a resolvable signingConfig, because the consumer can opt
 * into VPN detection regardless of whether the fingerprint binding is
 * configured.
 */
internal object BootstrapWiring {

    fun wire(
        project: Project,
        ext: DeviceIntelligenceExtension,
        variant: ApplicationVariant,
    ) {
        fun ident(len: Int): String {
            val head = ('a'..'z').random()
            val tail = (1 until len).map { (('a'..'z') + ('0'..'9')).random() }.joinToString("")
            return "$head$tail"
        }
        val pkg = "${ident(5)}.${ident(6)}"
        val providerCls = ident(8).replaceFirstChar { it.uppercase() }
        val factoryCls = ident(8).replaceFirstChar { it.uppercase() }
        val authority = ident(12)

        val variantTitle = variant.name.replaceFirstChar { it.uppercase() }
        val taskName = "generate${variantTitle}DeviceBootstrap"
        val srcDir = project.layout.buildDirectory
            .dir("generated/deviceintelligence/bootstrap/${variant.name}")
        val manFile = project.layout.buildDirectory
            .file("intermediates/deviceintelligence/${variant.name}/bootstrap-AndroidManifest.xml")

        val task = project.tasks.register<GenerateBootstrapTask>(taskName) {
            group = "deviceintelligence"
            description = "Generates the randomized RASP bootstrap (provider + factory) for variant '${variant.name}'."
            packageName.set(pkg)
            providerClass.set(providerCls)
            factoryClass.set(factoryCls)
            authoritySuffix.set(authority)
            variantName.set(variant.name)
            outputSourceDir.set(srcDir)
            outputManifest.set(manFile)
        }

        variant.sources.java?.addGeneratedSourceDirectory(task) { it.outputSourceDir }
        variant.sources.manifests.addGeneratedManifestFile(task) { it.outputManifest }

        project.afterEvaluate {
            if (ext.verbose.get()) {
                project.logger.lifecycle(
                    "deviceintelligence: registered ${task.name} (bootstrap -> $pkg.$providerCls / $pkg.$factoryCls)"
                )
            }
        }
    }
}
