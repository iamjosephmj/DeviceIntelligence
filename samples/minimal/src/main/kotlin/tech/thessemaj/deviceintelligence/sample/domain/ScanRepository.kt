package tech.thessemaj.deviceintelligence.sample.domain

import tech.thessemaj.deviceintelligence.sample.domain.model.Timed
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.ScanSession

/**
 * the seam between the app and the DeviceIntelligence SDK.
 *
 * The verifier's own types ([ScanResult], [ScanSession], …) are used as the domain
 * model rather than being re-mapped. They ARE the domain here — this app's whole
 * purpose is showing exactly what a backend receives — and a parallel set of
 * near-identical UI models would add forty fields of copying whose only effect
 * would be to hide a field when the SDK adds one.
 */
interface ScanRepository {

    /**
     * Registers the framework shim off the main thread at startup, without logging.
     *
     * Deliberately silent: `tools/qa/fp-harness.sh` and the device sweep parse the
     * first `initialize licensed=` line as the result of the button press, so a
     * warm-up that logged would shift what they read.
     */
    suspend fun warmUp()

    /** Validates the licence blob locally. No network, no TEE. */
    suspend fun initialize(): Timed<Boolean>

    /** Where the hardware attestation happens: one TEE/StrongBox keygen bound to [sessionId]. */
    suspend fun startSession(sessionId: String): Timed<Boolean>

    /** Produces one encrypted token for [reason]. */
    suspend fun scan(reason: String): Timed<String>

    /** The in-app "backend": decrypt, verify and grade the token. */
    suspend fun verify(token: String, sessionId: String, bound: ScanSession?): Result<ScanResult>

    /**
     * A fresh session id: opaque, unpredictable and per-session, because it is the
     * value the hardware attestation binds to. A guessable id removes replay
     * protection silently. 32 random bytes.
     */
    fun newSessionId(): String
}
