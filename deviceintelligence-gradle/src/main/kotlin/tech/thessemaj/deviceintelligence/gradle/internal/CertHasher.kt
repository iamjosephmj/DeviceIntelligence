package tech.thessemaj.deviceintelligence.gradle.internal

import java.io.File
import java.security.cert.X509Certificate

/**
 * Loads a keystore and produces SHA-256 hashes of the certificate(s)
 * associated with the given alias. Mirrors apksigner's "Signer #N
 * certificate SHA-256 digest" output, which is also what dicore's
 * native v2/v3 signing-block parser computes at runtime — so plugin and
 * runtime end up comparing identical hex strings.
 */
internal object CertHasher {

    /**
     * Returns the SHA-256 hex of every X.509 certificate in [alias]'s
     * chain. For typical Android keystores this is a single self-signed
     * cert, so the list usually has length 1.
     */
    fun digestChain(
        keystore: File,
        keystoreType: String?,
        keystorePassword: String,
        alias: String,
    ): List<String> {
        val ks = loadKeyStore(keystore, keystoreType, keystorePassword)

        val chain = ks.getCertificateChain(alias)
            ?: ks.getCertificate(alias)?.let { arrayOf(it) }
            ?: error("alias '$alias' not found in $keystore")

        return chain.map { cert ->
            require(cert is X509Certificate) { "non-X.509 cert in chain: ${cert::class}" }
            sha256Hex(cert.encoded)
        }
    }
}
