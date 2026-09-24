package tech.thessemaj.deviceintelligence.gradle.internal

import java.io.File
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Loads the consumer's signing key + certificate chain from a keystore, shared
 * by the APK ([tech.thessemaj.deviceintelligence.gradle.tasks.InstrumentApkTask]) and
 * AAB ([tech.thessemaj.deviceintelligence.gradle.tasks.BundleIntegrityTask]) integrity
 * paths so both derive identical signer-cert SHA-256 hashes.
 */
object KeystoreSigning {

    data class SigningMaterial(
        val privateKey: PrivateKey,
        val certs: List<X509Certificate>,
        /** SHA-256 hex of each cert in the chain (leaf first), lowercase. */
        val certHashes: List<String>,
    )

    fun load(
        keystoreFile: File,
        configuredType: String?,
        keystorePassword: String,
        alias: String,
        entryPassword: String?,
    ): SigningMaterial {
        val ks = loadKeyStore(keystoreFile, configuredType, keystorePassword)

        val pwd = (entryPassword ?: keystorePassword).toCharArray()
        val privateKey = ks.getKey(alias, pwd) as? PrivateKey
            ?: error("alias '$alias' has no PrivateKey entry in $keystoreFile")
        val rawChain = ks.getCertificateChain(alias)
            ?: ks.getCertificate(alias)?.let { arrayOf(it) }
            ?: error("alias '$alias' has no certificate in $keystoreFile")
        val certs = rawChain.map {
            require(it is X509Certificate) { "non-X.509 cert in chain: ${it::class}" }
            it
        }
        val certHashes = certs.map { sha256Hex(it.encoded) }
        return SigningMaterial(privateKey, certs, certHashes)
    }
}
