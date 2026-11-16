package tech.thessemaj.deviceintelligence.gradle.internal

import java.io.File
import java.io.FileInputStream
import java.security.KeyStore

/**
 * Keystore loading shared by [CertHasher] (signer cert hashes for the
 * diagnostic compute task) and [KeystoreSigning] (private key + certs for the
 * re-sign path). One home for the type-fallback dance so both callers accept
 * exactly the same keystores.
 */
internal fun loadKeyStore(
    keystoreFile: File,
    configuredType: String?,
    keystorePassword: String,
): KeyStore {
    require(keystoreFile.isFile) { "keystore not found: $keystoreFile" }

    // The configured `storeType` is sometimes unreliable across AGP
    // versions (older debug keystores are JKS; new ones default to
    // PKCS12). Try the configured type first and then fall back, so
    // we never fail on a benign type mismatch.
    val candidates = buildList {
        if (!configuredType.isNullOrEmpty()) add(configuredType.uppercase())
        add("PKCS12")
        add("JKS")
    }.distinct()

    var lastError: Throwable? = null
    for (type in candidates) {
        try {
            val ks = KeyStore.getInstance(type)
            FileInputStream(keystoreFile).use { ks.load(it, keystorePassword.toCharArray()) }
            return ks
        } catch (e: Throwable) {
            lastError = e
        }
    }
    throw IllegalStateException(
        "Failed to load keystore $keystoreFile as any of $candidates",
        lastError,
    )
}
