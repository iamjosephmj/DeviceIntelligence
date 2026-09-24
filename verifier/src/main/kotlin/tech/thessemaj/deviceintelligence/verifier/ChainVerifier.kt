package tech.thessemaj.deviceintelligence.verifier

import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Validates the token's attestation cert chain: each cert signed by the next, and
 * the top signed by (or equal to) a pinned Google root. Port of
 * verify_token.py `_verify_chain_to_pinned` / `_verify_signed_by`.
 */
internal class ChainVerifier(private val pinnedRoots: List<X509Certificate>) {

    fun parseChain(certsHex: List<String>): List<X509Certificate> {
        val cf = CertificateFactory.getInstance("X.509")
        return certsHex.map { hex ->
            cf.generateCertificate(Hex.decode(hex).inputStream()) as X509Certificate
        }
    }

    /** Throws if [cert] is not signed by [issuer]'s public key. */
    private fun verifySignedBy(cert: X509Certificate, issuer: X509Certificate) {
        cert.verify(issuer.publicKey)   // signature only — validity dates are not our gate
    }

    private fun sha256Fp(cert: X509Certificate): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(cert.encoded)

    /** Returns the pinned root the chain terminates in, or throws. */
    fun verifyToPinnedRoot(chain: List<X509Certificate>): X509Certificate {
        require(chain.isNotEmpty()) { "empty chain" }
        for (i in 0 until chain.size - 1) verifySignedBy(chain[i], chain[i + 1])
        val top = chain.last()
        val topFp = sha256Fp(top)
        for (root in pinnedRoots) {
            if (topFp.contentEquals(sha256Fp(root))) return root
            try {
                verifySignedBy(top, root)
                return root
            } catch (_: Exception) { /* try next root */ }
        }
        throw IllegalArgumentException("chain top does not chain to a pinned Google root")
    }
}
