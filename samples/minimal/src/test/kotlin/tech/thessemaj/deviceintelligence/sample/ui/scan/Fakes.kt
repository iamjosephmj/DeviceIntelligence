package tech.thessemaj.deviceintelligence.sample.ui.scan

import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.model.Timed
import tech.thessemaj.deviceintelligence.verifier.Assurance
import tech.thessemaj.deviceintelligence.verifier.Check
import tech.thessemaj.deviceintelligence.verifier.CheckKind
import tech.thessemaj.deviceintelligence.verifier.ResolvedSignal
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.ScanSession

/**
 * A [ScanRepository] with no SDK behind it.
 *
 * Every knob here corresponds to a real device outcome the testbed exists to
 * render: a rejected licence, a TEE keygen that failed, a token that could not be
 * produced, a verifier that threw.
 */
class FakeScanRepository : ScanRepository {

    var licensed: Boolean = true
    var attested: Boolean = true
    var token: String = "aabbcc"
    var verifyFailure: Throwable? = null
    var warmedUp: Boolean = false
        private set

    val session: ScanSession = ScanSession(
        attestedKey = "0".repeat(64),
        attestedApp = null,
        assurance = Assurance.STRONGBOX,
        bootState = "Verified",
        deviceLocked = true,
    )

    var result: ScanResult = scanResult()

    override suspend fun warmUp() { warmedUp = true }

    override suspend fun initialize() = Timed(licensed, 12L)

    override suspend fun startSession(sessionId: String) = Timed(attested, 340L)

    override suspend fun scan(reason: String) = Timed(token, 45L)

    override suspend fun verify(
        token: String,
        sessionId: String,
        bound: ScanSession?,
    ): Result<ScanResult> =
        verifyFailure?.let { Result.failure(it) } ?: Result.success(result)

    override fun newSessionId(): String = "0".repeat(64)
}

fun scanResult(
    ok: Boolean = true,
    bootstrap: Boolean = true,
    deviceIntegrityOk: Boolean = true,
    session: ScanSession? = null,
    checks: List<Check> = listOf(
        Check("token decrypts", true, "", CheckKind.AUTH),
        Check("hardware backed", true, "", CheckKind.INTEGRITY),
    ),
    signals: List<ResolvedSignal> = emptyList(),
    reason: String? = null,
) = ScanResult(
    ok = ok,
    bootstrap = bootstrap,
    deviceIntegrityOk = deviceIntegrityOk,
    session = session,
    checks = checks,
    signals = signals,
    reason = reason,
)

fun blockingSignal() = ResolvedSignal(
    id = "INTEL_0008",
    detector = "art",
    kind = "hook",
    title = "ART method entrypoint rewritten",
    severity = "HIGH",
    detail = "entrypoint diverges from the class linker's table addr=0x7f1c2a",
    blocking = true,
)
