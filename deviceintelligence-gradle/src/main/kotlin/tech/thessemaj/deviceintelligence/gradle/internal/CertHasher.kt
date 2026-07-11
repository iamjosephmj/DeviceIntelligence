package tech.thessemaj.deviceintelligence.gradle.internal

import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.MessageDigest
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
        require(keystore.isFile) { "keystore not found: $keystore" }

        // The configured `storeType` is sometimes unreliable across AGP
        // versions (older debug keystores are JKS; new ones default to
        // PKCS12). Try the configured type first and then fall back, so
        // we never fail on a benign type mismatch.
        val candidates = buildList {
            if (!keystoreType.isNullOrEmpty()) add(keystoreType.uppercase())
            add("PKCS12")
            add("JKS")
        }.distinct()

        var lastError: Throwable? = null
        var ks: KeyStore? = null
        for (type in candidates) {
            try {
                val candidate = KeyStore.getInstance(type)
                FileInputStream(keystore).use { candidate.load(it, keystorePassword.toCharArray()) }
                ks = candidate
                break
            } catch (e: Throwable) {
                lastError = e
            }
        }
        ks ?: throw IllegalStateException(
            "Failed to load keystore $keystore as any of $candidates",
            lastError,
        )

        val chain = ks.getCertificateChain(alias)
            ?: ks.getCertificate(alias)?.let { arrayOf(it) }
            ?: error("alias '$alias' not found in $keystore")

        val md = MessageDigest.getInstance("SHA-256")
        return chain.map { cert ->
            require(cert is X509Certificate) { "non-X.509 cert in chain: ${cert::class}" }
            md.reset()
            md.digest(cert.encoded).toHex()
        }
    }
}

private fun ByteArray.toHex(): String {
    val hex = "0123456789abcdef".toCharArray()
    val out = CharArray(size * 2)
    for (i in indices) {
        out[i * 2]     = hex[(this[i].toInt() shr 4) and 0xF]
        out[i * 2 + 1] = hex[this[i].toInt() and 0xF]
    }
    return String(out)
}
