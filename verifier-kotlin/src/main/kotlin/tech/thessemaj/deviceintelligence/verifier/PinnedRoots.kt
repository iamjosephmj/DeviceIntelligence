package tech.thessemaj.deviceintelligence.verifier

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * The pinned Google hardware-attestation roots — the trust anchors a genuine
 * KeyMint attestation chain must terminate in. Loaded from a bundled resource
 * (mirror of the native `kGoogleAttestRoots` / verify_token.py `PINNED_ROOTS_B64`).
 */
object PinnedRoots {
    private const val RESOURCE = "/pinned-roots.txt"

    /** The roots shipped with :verifier. Loaded once, on first use. */
    val default: List<X509Certificate> by lazy { fromResource(RESOURCE) }

    /**
     * Load roots from a classpath resource. Use this to pin your own set rather than
     * the bundled one — the bundled roots go stale when Google publishes a new root,
     * and a stale set rejects genuine devices on newer hardware.
     */
    fun fromResource(path: String): List<X509Certificate> {
        val text = PinnedRoots::class.java.getResourceAsStream(path)
            ?.bufferedReader()?.use { it.readText() }
            ?: throw IllegalStateException("pinned roots resource not found: $path")
        return parse(text)
    }

    /** Parse base64-DER roots, one per line; `#` comments and blank lines are ignored. */
    fun parse(text: String): List<X509Certificate> {
        val cf = CertificateFactory.getInstance("X.509")
        return text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { b64 ->
                cf.generateCertificate(Base64.getDecoder().decode(b64).inputStream()) as X509Certificate
            }
            .toList()
    }
}
