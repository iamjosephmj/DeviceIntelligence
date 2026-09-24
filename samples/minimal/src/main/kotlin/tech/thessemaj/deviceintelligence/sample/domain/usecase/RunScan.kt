package tech.thessemaj.deviceintelligence.sample.domain.usecase

import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.model.ScanOutcome
import tech.thessemaj.deviceintelligence.verifier.ScanSession
import javax.inject.Inject

/** Phase 2: scan (device) + decrypt, verify and decide (in-app backend). */
class RunScan @Inject constructor(
    private val repository: ScanRepository,
) {
    suspend operator fun invoke(sessionId: String, bound: ScanSession?): ScanOutcome {
        val token = repository.scan(REASON)
        if (token.value.isEmpty()) return ScanOutcome.NoToken

        return repository.verify(token.value, sessionId, bound).fold(
            onSuccess = { ScanOutcome.Verified(it, token.value.length / 2, token.millis) },
            onFailure = { ScanOutcome.VerifyError(it) },
        )
    }

    private companion object {
        const val REASON = "checkout"
    }
}
