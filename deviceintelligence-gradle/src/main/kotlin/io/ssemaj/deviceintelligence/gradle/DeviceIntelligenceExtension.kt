package io.ssemaj.deviceintelligence.gradle

import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty

/**
 * Consumer-facing DSL block. Real options (reaction policy, detector set,
 * pepper, etc.) layer on in subsequent flags. For now this is a stable
 * placeholder so the plugin applies and the DSL block is reachable.
 */
abstract class DeviceIntelligenceExtension {
    /** Plugin verbosity at configuration time. */
    abstract val verbose: Property<Boolean>

    /** Reserved for the detector toggle set; unused at L4. */
    abstract val detectors: SetProperty<String>

    /**
     * Opt in to VPN detection on the consumer's APK.
     *
     * When `true`, the plugin injects
     * `<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />`
     * into the consumer's variant manifest via AGP's
     * `addGeneratedManifestFile`, which is the only thing that lets
     * `DeviceContext.vpnActive` populate at runtime
     * (`ConnectivityManager.getNetworkCapabilities` requires
     * `ACCESS_NETWORK_STATE`).
     *
     * Default is `false`, so the library manifest itself is
     * permissionless after merge. Apps that don't care about VPN
     * detection ship without the permission and `vpnActive` shows up
     * as `null` in the report, which is graceful degradation.
     *
     * `ACCESS_NETWORK_STATE` is `normal`-protection — no runtime
     * prompt, no Play Store sensitive-permission review.
     */
    abstract val enableVpnDetection: Property<Boolean>
}
