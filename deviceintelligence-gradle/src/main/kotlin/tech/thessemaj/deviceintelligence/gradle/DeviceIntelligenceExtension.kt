package tech.thessemaj.deviceintelligence.gradle

import org.gradle.api.Action
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Nested

/**
 * The `deviceintelligence { }` block a consumer configures the plugin with.
 *
 * Every option is opt-in and defaults to off, so applying the plugin and writing
 * nothing is the supported path. What each one costs — the permission it injects,
 * the dependency it adds — is spelled out in `deviceintelligence-gradle/README.md`.
 */
abstract class DeviceIntelligenceExtension {

    /** Log what the plugin registers, at configuration time. Default `false`. */
    abstract val verbose: Property<Boolean>

    /**
     * Stop the plugin adding the matching runtime AAR to `implementation`.
     *
     * Default `false`. Set it only when pinning the runtime by hand — keeping the
     * plugin and runtime versions in step then becomes your problem, and a
     * mismatched pair fails at runtime rather than at build time. The build-time
     * work still runs either way. Also available as
     * `-Pdeviceintelligence.disableAutoRuntimeDependency=true`.
     */
    abstract val disableAutoRuntimeDependency: Property<Boolean>

    /**
     * App Bundle integrity. Mutually exclusive with the APK transform per variant:
     * when enabled, the plugin bakes into the AAB and re-signs it instead of
     * instrumenting the APK.
     */
    @get:Nested
    abstract val appBundle: AppBundleOptions

    /** DSL sugar: `deviceintelligence { appBundle { enabled = true } }`. */
    fun appBundle(action: Action<AppBundleOptions>) = action.execute(appBundle)
}
