package tech.thessemaj.deviceintelligence.sample.domain.model

import tech.thessemaj.deviceintelligence.verifier.ScanResult

/**
 * The policy call, which belongs to the CALLER — [tech.thessemaj.deviceintelligence.verifier.ScanVerifier]
 * grades, it does not decide. A failed gate means the token is not authentic; a
 * blocking signal means it is authentic but the device is not trustworthy.
 */
enum class Verdict {
    /** A failed AUTH gate is a proven forgery — nothing in the token is usable. */
    REJECT,

    /**
     * Authentic, but the device honestly reports an untrustworthy state, or a
     * detector fired hard enough for policy to block on it.
     */
    COMPROMISED,

    TRUSTWORTHY,
    ;

    companion object {
        fun of(r: ScanResult): Verdict = when {
            !r.ok -> REJECT
            !r.deviceIntegrityOk || r.signals.any { it.blocking } -> COMPROMISED
            else -> TRUSTWORTHY
        }
    }
}
