package tech.thessemaj.deviceintelligence.gradle.internal

import tech.thessemaj.deviceintelligence.gradle.DeviceIntelligenceExtension
import org.gradle.api.Project

/**
 * The plugin's auto-wiring of the matching DeviceIntelligence runtime AAR into the
 * consumer's `implementation` configuration, so applying the plugin alone is
 * enough — no `implementation("...:deviceintelligence:X")` line needed in the consumer's
 * `dependencies {}` block.
 *
 * Three resolution paths, in order:
 *
 * 1. **Opted out.** If the consumer set
 *    `deviceintelligence { disableAutoRuntimeDependency = true }`
 *    or passed `-Pdeviceintelligence.disableAutoRuntimeDependency=true`,
 *    we do nothing — the consumer manages the AAR themselves.
 *
 * 2. **In-tree (monorepo) substitution.** If
 *    `:deviceintelligence` exists as a sibling project of the
 *    consumer (true inside this repo's `samples/minimal`), we add
 *    a project-dependency on it. This keeps the dev loop fast: a
 *    change in `deviceintelligence/src/main/kotlin/...` is picked
 *    up by the next `assembleDebug` without a publish step.
 *
 * 3. **Published coordinate.** Otherwise we add the published AAR
 *    coordinate, locked to the same version the plugin itself was
 *    built under. Same-version-as-plugin is what makes the
 *    fingerprint-binary format stable: the plugin bakes a baseline
 *    that the runtime reads, and a version mismatch between the
 *    two would silently corrupt integrity.apk's verdict.
 *
 * The dependency is only added if a `com.android.application` or
 * `com.android.library` plugin is also applied — without an Android
 * plugin there's no `implementation` configuration to add to.
 */
internal object RuntimeDependencyWiring {

    /**
     * Auto-apply the matching runtime AAR. Eager registration (not
     * afterEvaluate) is required because Android source-set
     * resolution against `implementation` reads dependencies during
     * configuration; an afterEvaluate add lands too late and the
     * runtime classes don't make it onto the consumer's classpath.
     */
    fun wire(project: Project, ext: DeviceIntelligenceExtension) {
        val cliOptOut = project.providers.gradleProperty(
            "deviceintelligence.disableAutoRuntimeDependency"
        ).map { it.toBoolean() }.getOrElse(false)

        project.plugins.withId("com.android.application") { addRuntimeDep(project, ext, cliOptOut) }
        project.plugins.withId("com.android.library") { addRuntimeDep(project, ext, cliOptOut) }
    }

    private fun addRuntimeDep(
        project: Project,
        ext: DeviceIntelligenceExtension,
        cliOptOut: Boolean,
    ) {
        if (cliOptOut || ext.disableAutoRuntimeDependency.get()) {
            if (ext.verbose.get()) {
                project.logger.lifecycle(
                    "deviceintelligence: auto-runtime-dependency disabled; consumer must add " +
                        "implementation(\"${PluginCoordinates.GROUP_ID}:" +
                        "${PluginCoordinates.LIBRARY_ARTIFACT_ID}:" +
                        "${PluginCoordinates.VERSION}\") themselves."
                )
            }
            return
        }

        // In-tree (monorepo) substitution. The plugin's apply() is invoked in
        // the consumer's build context, so `rootProject.findProject(":deviceintelligence")`
        // returns non-null only when the consumer's root build also contains
        // our AAR module. That's exactly the dev-loop case (samples/minimal).
        val inTree = project.rootProject.findProject(":${PluginCoordinates.LIBRARY_ARTIFACT_ID}")
        if (inTree != null && inTree != project) {
            project.dependencies.add(
                "implementation",
                project.dependencies.project(mapOf("path" to inTree.path))
            )
            if (ext.verbose.get()) {
                project.logger.lifecycle(
                    "deviceintelligence: auto-runtime-dependency wired as project(${inTree.path}) (in-tree dev loop)"
                )
            }
            return
        }

        val coord = "${PluginCoordinates.GROUP_ID}:" +
            "${PluginCoordinates.LIBRARY_ARTIFACT_ID}:" +
            PluginCoordinates.VERSION
        project.dependencies.add("implementation", coord)
        if (ext.verbose.get()) {
            project.logger.lifecycle("deviceintelligence: auto-runtime-dependency wired as $coord")
        }
    }
}
