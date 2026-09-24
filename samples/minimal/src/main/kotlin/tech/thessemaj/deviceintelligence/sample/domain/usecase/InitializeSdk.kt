package tech.thessemaj.deviceintelligence.sample.domain.usecase

import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.model.InitStep
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import javax.inject.Inject

/**
 * Phase 1: validate the licence locally, then hand the SDK a fresh session id.
 *
 * `setSession` is where the one TEE keygen happens. It is deliberately here and not
 * on the scan path — which is what makes every later scan cheap, and why the two
 * stages are reported separately.
 */
class InitializeSdk @Inject constructor(
    private val repository: ScanRepository,
) {
    operator fun invoke(): Flow<InitStep> = flow {
        val licence = repository.initialize()
        if (!licence.value) {
            emit(InitStep.LicenceRejected(licence.millis))
            return@flow
        }
        emit(InitStep.LicenceAccepted(licence.millis))

        // In a real app this is YOUR backend's session id, handed over after login.
        val sessionId = repository.newSessionId()
        val attest = repository.startSession(sessionId)
        emit(
            if (attest.value) {
                InitStep.SessionAttested(attest.millis, sessionId)
            } else {
                InitStep.SessionFailed(attest.millis)
            },
        )
    }
}
