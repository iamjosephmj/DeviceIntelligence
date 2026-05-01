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

    /**
     * Opt in to biometrics-enrollment detection on the consumer's APK.
     *
     * When `true`, the plugin injects
     * `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
     * into the consumer's variant manifest. That's the gate
     * `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)` checks
     * before answering — without it, the call throws SecurityException
     * and `DeviceContext.biometricsEnrolled` reports `null` (graceful
     * degradation).
     *
     * Default is `false` for parity with the rest of the opt-in
     * surface — apps that don't use the biometric prompt and don't
     * care about cohorting on enrollment status ship without the
     * permission.
     *
     * `USE_BIOMETRIC` is `normal`-protection — no runtime prompt, no
     * Play Store sensitive-permission review. Banking / wallet apps
     * that already wire `BiometricPrompt` declare it anyway, in which
     * case the merge is a no-op.
     */
    abstract val enableBiometricsDetection: Property<Boolean>

    /**
     * Opt OUT of the plugin's auto-applied runtime AAR dependency.
     *
     * By default the plugin adds the matching `deviceintelligence`
     * runtime AAR to the consumer's `implementation` configuration —
     * same group + same version as the plugin itself. This is the
     * single-line-integration story documented in the README and the
     * mechanism that makes plugin-vs-runtime version skew impossible.
     *
     * Set to `true` only when you want to manage the runtime
     * dependency by hand — for example when consuming a SNAPSHOT AAR
     * from a private repo, or when shipping the runtime as a transitive
     * dependency of a wrapper module the plugin can't see. When opted
     * out, the build-time work (fingerprint baking, manifest injection)
     * still runs; the consumer is responsible for adding
     * `implementation("...:deviceintelligence:<matching version>")`
     * themselves.
     *
     * Default `false`. Equivalent escape hatch via the command line:
     * `-Pdeviceintelligence.disableAutoRuntimeDependency=true`.
     */
    abstract val disableAutoRuntimeDependency: Property<Boolean>

    /**
     * Opt OUT of anonymous device-hardware telemetry.
     *
     * DeviceIntelligence collects hardware-level signals from the native
     * layer (ABI, API level, manufacturer, model, SoC, CPU vendor from
     * emulator probe, ART/native integrity result codes, mount filesystem
     * types, loaded library basenames) and sends them to Firebase
     * Measurement Protocol to help improve the SDK's detector accuracy.
     *
     * No package names, certificate hashes, memory addresses, user
     * identifiers, or any app-specific data are ever collected.
     * The "client_id" is a one-way SHA-256 of `ro.build.fingerprint`
     * and cannot be reversed to any user or device identifier.
     *
     * Analytics are **enabled by default**. Set to `true` to opt out.
     * When opted out, the plugin injects a manifest `<meta-data>` tag
     * that the native layer reads at startup and uses to skip all
     * tracking work entirely (no threads started, no HTTP calls made).
     *
     * Default `false` (analytics on).
     */
    abstract val disableAnalytics: Property<Boolean>
}
