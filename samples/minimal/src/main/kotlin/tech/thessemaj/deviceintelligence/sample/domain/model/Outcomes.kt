package tech.thessemaj.deviceintelligence.sample.domain.model

import tech.thessemaj.deviceintelligence.verifier.ScanResult

/**
 * The Initialize phase, reported one stage at a time.
 *
 * Emitted as a stream rather than returned as a single result so the screen can
 * show the pipeline executing: the licence stage settles while the TEE keygen —
 * which is the slow one, often several hundred milliseconds — is still running.
 *
 * Note that neither failure is a dead end: a rejected licence and a failed keygen
 * both still let `scan()` emit a DEGRADED token, because silence is what an
 * attacker wants — at the backend it is indistinguishable from a network error or
 * no SDK at all.
 */
sealed interface InitStep {
    val millis: Long

    data class LicenceAccepted(override val millis: Long) : InitStep

    /** `server.key` is expired or bound to a different package. */
    data class LicenceRejected(override val millis: Long) : InitStep

    data class SessionAttested(override val millis: Long, val sessionId: String) : InitStep

    /** The case a hook engine engineers on purpose, so the one that must still report. */
    data class SessionFailed(override val millis: Long) : InitStep
}

/** The result of the Scan phase: device produces a token, in-app backend verifies it. */
sealed interface ScanOutcome {
    data class Verified(
        val result: ScanResult,
        val tokenBytes: Int,
        val millis: Long,
    ) : ScanOutcome

    /**
     * The one failure that cannot emit even a degraded token: the licence blob did
     * not parse at all, and the server public key lives inside it.
     */
    data object NoToken : ScanOutcome

    /**
     * `verifyScan` returns a populated [ScanResult] for every EXPECTED failure, so a
     * THROW is a bug or an environment gap — never a policy rejection.
     */
    data class VerifyError(val cause: Throwable) : ScanOutcome
}
