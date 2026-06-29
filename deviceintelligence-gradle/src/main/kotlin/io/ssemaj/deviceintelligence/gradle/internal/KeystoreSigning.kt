// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/KeystoreSigning.kt
package io.ssemaj.deviceintelligence.gradle.internal

import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Shared keystore-load helper shared between [InstrumentApkTask] and
 * [BundleIntegrityTask]. Extracted here so both tasks load signing material
 * identically without duplicating the PKCS12 / JKS fallback logic.
 */
internal object KeystoreSigning {

    data class Material(
        val privateKey: PrivateKey,
        val certs: List<X509Certificate>,
        val certHashes: List<String>,
    )

    /**
     * Load [Material] from [keystoreFile]. Tries [configuredType] first (if non-null),
     * then PKCS12, then JKS. Throws [IllegalStateException] if none succeeds.
     */
    fun load(
        keystoreFile: File,
        configuredType: String?,
        keystorePassword: String,
        alias: String,
        entryPassword: String?,
    ): Material {
        require(keystoreFile.isFile) { "keystore not found: $keystoreFile" }

        val candidates = buildList {
            if (!configuredType.isNullOrEmpty()) add(configuredType.uppercase())
            add("PKCS12")
            add("JKS")
        }.distinct()

        var ks: KeyStore? = null
        var lastError: Throwable? = null
        for (type in candidates) {
            try {
                val candidate = KeyStore.getInstance(type)
                FileInputStream(keystoreFile).use { candidate.load(it, keystorePassword.toCharArray()) }
                ks = candidate
                break
            } catch (e: Throwable) {
                lastError = e
            }
        }
        ks ?: throw IllegalStateException(
            "Failed to load keystore $keystoreFile as any of $candidates",
            lastError,
        )

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
        val md = MessageDigest.getInstance("SHA-256")
        val certHashes = certs.map { cert ->
            md.reset()
            md.digest(cert.encoded).joinToString("") { b -> "%02x".format(b) }
        }
        return Material(privateKey, certs, certHashes)
    }
}
