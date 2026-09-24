package tech.thessemaj.deviceintelligence.gradle

import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty

/**
 * Opt-in App Bundle integrity ("bundle mode").
 *
 * When [enabled], the plugin bakes a bundle-mode fingerprint (decompressed
 * dex/`.so` hashes + signer pins) into the AAB's base assets and re-signs the
 * AAB, instead of instrumenting the APK. The runtime then hashes those entries'
 * decompressed bodies across `sourceDir ∪ splitSourceDirs` and checks the
 * installed signer is a member of the baked allow-set.
 *
 * APK mode and bundle mode are mutually exclusive per variant; turning this on
 * skips the APK integrity transform (see DeviceIntelligencePlugin).
 */
abstract class AppBundleOptions {
    /** Enable bundle mode for AAB builds. Default `false`. */
    abstract val enabled: Property<Boolean>

    /**
     * Play App Signing certificate SHA-256(s) to pin, normalized to lowercase
     * hex with any `:` separators stripped. Under Play App Signing, Google
     * re-signs the delivered APKs with the app signing key, so the runtime must
     * accept that signer in addition to (or instead of) the upload key. Empty =
     * no signer membership check is baked.
     */
    abstract val playSigningCertSha256: SetProperty<String>

    /** DSL sugar: `appBundle { playSigningCertSha256("AB:CD:...") }`. */
    fun playSigningCertSha256(vararg hex: String) {
        for (h in hex) playSigningCertSha256.add(h.replace(":", "").lowercase())
    }
}
