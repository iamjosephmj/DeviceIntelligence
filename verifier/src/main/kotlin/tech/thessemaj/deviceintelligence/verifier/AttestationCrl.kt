package tech.thessemaj.deviceintelligence.verifier

import java.security.cert.X509Certificate

/**
 * Offline keybox-revocation list — the backend port of the RASP's on-device
 * `attest_crl`. Google publishes an attestation status list of revoked/compromised
 * attestation keys (leaked keyboxes); an enrollment whose cert chain contains any
 * revoked serial is a spoofer reusing published key material, so enrollment fails
 * closed. This complements the cross-level keybox-reuse check
 * ([EnrollVerifier.crossLevelSpoofed]): reuse catches "the same batch key across
 * StrongBox and TEE", revocation catches "this exact keybox is known-compromised".
 *
 * Serials are compared as lowercase hex with no leading zeros — the form
 * `BigInteger.toString(16)` yields and the form Google's status-list keys use, so a
 * chain cert's `serialNumber` maps directly to a list entry.
 */
class AttestationCrl(private val revoked: Set<String>) {

    /** Whether this certificate's serial appears on the revocation list. */
    fun isRevoked(cert: X509Certificate): Boolean = normalize(cert.serialNumber.toString(16)) in revoked

    /** The first revoked serial (normalized hex) found across [chains], or null. */
    /**
     * The first revoked serial found across the given chains, or null if none are revoked.
     * Returns the serial rather than a boolean so the caller can log which key was leaked.
     */
    fun firstRevoked(vararg chains: List<X509Certificate>): String? {
        for (chain in chains) for (cert in chain) if (isRevoked(cert)) return normalize(cert.serialNumber.toString(16))
        return null
    }

    /** How many serials are on the list. Zero means the CRL failed to load — fail closed. */
    val size: Int get() = revoked.size

    companion object {
        private const val RESOURCE = "/attestation-crl.txt"

        /** The bundled revocation list (an offline mirror of Google's status list). */
        val default: AttestationCrl by lazy { fromResource(RESOURCE) }

        fun fromResource(path: String): AttestationCrl {
            val text = AttestationCrl::class.java.getResourceAsStream(path)
                ?.bufferedReader()?.use { it.readText() } ?: ""
            return parse(text)
        }

        /** One serial per line; `#` starts a comment; blank lines ignored. */
        fun parse(text: String): AttestationCrl =
            AttestationCrl(
                text.lineSequence()
                    .map { it.substringBefore('#').trim() }
                    .filter { it.isNotEmpty() }
                    .map { normalize(it) }
                    .toSet(),
            )

        private fun normalize(serialHex: String): String =
            serialHex.removePrefix("0x").lowercase().trimStart('0').ifEmpty { "0" }
    }
}
