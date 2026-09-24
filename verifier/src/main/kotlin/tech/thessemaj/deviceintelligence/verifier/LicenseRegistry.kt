package tech.thessemaj.deviceintelligence.verifier

/**
 * Which (package, signing certificate) pairs may run this SDK.
 *
 * Keyed on BOTH, because a repackager keeps the applicationId but cannot keep the
 * signing key — so a package-name-only table would licence the attacker's build
 * alongside the real one.
 *
 * This is consulted against the identity read out of the hardware attestation
 * (tag 709), never against anything the device self-reported.
 */
interface LicenseRegistry {
    /**
     * Whether this app identity is licensed to use DeviceIntelligence. Both values come from the
     * TEE-attested `attestationApplicationId`, not from anything the app self-reported.
     */
    fun isLicensed(packageName: String, signatureDigest: String): Boolean
}

/**
 * Licenses everything. The default, so an embedder that has not configured a table
 * sees no behaviour change — licensing is opt-in, and this codebase grades rather
 * than gates.
 */
object OpenLicenseRegistry : LicenseRegistry {
    override fun isLicensed(packageName: String, signatureDigest: String) = true
}

/** Fixed table of applicationId -> allowed SHA-256 signing-cert digests (hex). */
class StaticLicenseRegistry(entries: Map<String, Set<String>>) : LicenseRegistry {
    private val table = entries.mapValues { (_, v) -> v.map { it.lowercase() }.toSet() }

    override fun isLicensed(packageName: String, signatureDigest: String): Boolean =
        table[packageName]?.contains(signatureDigest.lowercase()) == true
}
