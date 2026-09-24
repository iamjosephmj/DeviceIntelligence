package tech.thessemaj.deviceintelligence.sample.ui.scan

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import tech.thessemaj.deviceintelligence.sample.BuildConfig
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.data.ChaosHook
import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.model.InitStep
import tech.thessemaj.deviceintelligence.sample.domain.model.ScanOutcome
import tech.thessemaj.deviceintelligence.sample.domain.model.Verdict
import tech.thessemaj.deviceintelligence.sample.domain.usecase.InitializeSdk
import tech.thessemaj.deviceintelligence.sample.domain.usecase.RunScan
import tech.thessemaj.deviceintelligence.sample.ui.text.UiText
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ScanViewModel @Inject constructor(
    private val initializeSdk: InitializeSdk,
    private val runScan: RunScan,
    repository: ScanRepository,
    /** Debug-only red-team hook; null keeps the device-free unit tests constructing this. */
    private val chaos: ChaosHook? = null,
) : ViewModel() {

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    /** The app's own session id — in a real app this comes from your login. */
    private var sessionId: String = ""

    init {
        // Warm the core off the main thread, as the Activity used to do in onCreate.
        viewModelScope.launch { repository.warmUp() }
    }

    /**
     * Initialize runs once per process.
     *
     * The button is disabled as soon as it completes, whatever the outcome — a
     * second run would discard the session and pay for another TEE keygen, and the
     * failure cases have already reported everything they are going to. Restart the
     * app for a fresh session.
     */
    /** The single button: whatever it says, this is what it does. */
    fun onAction() {
        when (_state.value.action) {
            ScanAction.Initialize -> onInitialize()
            ScanAction.Scan, ScanAction.Rescan -> onScan()
        }
    }

    fun onInitialize() {
        _state.update {
            it.copy(
                stages = ScanUiState.IdleStages.mapIndexed { i, s ->
                    if (i == ScanUiState.LICENCE) s.copy(state = StageState.Running) else s
                },
                verdict = null,
                note = null,
                metrics = emptyList(),
                actionEnabled = false,
                result = null,
            )
        }
        viewModelScope.launch {
            initializeSdk().collect { step -> apply(step) }
        }
    }

    private fun apply(step: InitStep) = _state.update { s ->
        when (step) {
            is InitStep.LicenceAccepted -> s.copy(
                stages = s.stage(ScanUiState.LICENCE, StageState.Done, step.millis)
                    .mapIndexed { i, st ->
                        if (i == ScanUiState.SESSION) st.copy(state = StageState.Running) else st
                    },
            )

            is InitStep.LicenceRejected -> s.copy(
                stages = s.stage(ScanUiState.LICENCE, StageState.Failed, step.millis),
                verdict = R.string.status_no_licence,
                verdictTone = Tone.Warn,
                note = UiText.of(R.string.note_no_licence),
                noteTone = Tone.Neutral,
                action = ScanAction.Scan,
                actionEnabled = true,
            )

            is InitStep.SessionFailed -> s.copy(
                stages = s.stage(ScanUiState.SESSION, StageState.Failed, step.millis),
                verdict = R.string.status_no_attestation,
                verdictTone = Tone.Warn,
                note = UiText.of(R.string.note_no_attestation),
                noteTone = Tone.Neutral,
                action = ScanAction.Scan,
                actionEnabled = true,
            )

            is InitStep.SessionAttested -> {
                sessionId = step.sessionId
                s.copy(
                    stages = s.stage(ScanUiState.SESSION, StageState.Done, step.millis),
                    verdict = R.string.status_ready,
                    verdictTone = Tone.Good,
                    note = UiText.of(R.string.note_ready, step.sessionId),
                    noteTone = Tone.Neutral,
                    action = ScanAction.Scan,
                    actionEnabled = true,
                    // A new session must re-bootstrap.
                    boundSession = null,
                )
            }
        }
    }

    fun onScan() {
        _state.update {
            it.copy(
                stages = it.stage(ScanUiState.SCAN, StageState.Running),
                verdict = null,
                note = null,
                metrics = emptyList(),
                actionEnabled = false,
                result = null,
            )
        }
        viewModelScope.launch {
            when (val outcome = runScan(sessionId, _state.value.boundSession)) {
                ScanOutcome.NoToken -> _state.update {
                    it.copy(
                        stages = it.stage(ScanUiState.SCAN, StageState.Failed),
                        verdict = R.string.status_no_token,
                        verdictTone = Tone.Bad,
                        note = UiText.of(R.string.note_no_token),
                        noteTone = Tone.Bad,
                        action = ScanAction.Rescan,
                        // Nothing further to try: the blob the key lives in did not parse.
                        actionEnabled = false,
                    )
                }

                is ScanOutcome.VerifyError -> _state.update {
                    it.copy(
                        stages = it.stage(ScanUiState.SCAN, StageState.Failed),
                        verdict = R.string.status_verify_error,
                        verdictTone = Tone.Bad,
                        note = UiText.of(
                            R.string.note_verify_error,
                            outcome.cause.javaClass.simpleName,
                            outcome.cause.message.orEmpty(),
                        ),
                        noteTone = Tone.Bad,
                        action = ScanAction.Rescan,
                        actionEnabled = true,
                    )
                }

                is ScanOutcome.Verified -> {
                    val r = outcome.result
                    val verdict = Verdict.of(r)
                    _state.update {
                        it.copy(
                            stages = it.stage(ScanUiState.SCAN, StageState.Done, outcome.millis),
                            verdict = when (verdict) {
                                Verdict.REJECT -> R.string.verdict_reject
                                Verdict.COMPROMISED -> R.string.verdict_compromised
                                Verdict.TRUSTWORTHY -> R.string.verdict_trustworthy
                            },
                            verdictTone = when (verdict) {
                                Verdict.REJECT -> Tone.Bad
                                Verdict.COMPROMISED -> Tone.Warn
                                Verdict.TRUSTWORTHY -> Tone.Good
                            },
                            // Which KIND of scan this was. A steady-state scan legitimately
                            // carries less than a bootstrap — no chain, no full fingerprint —
                            // and without this the second scan looks like it lost checks.
                            note = scanNote(r.bootstrap, r.reason),
                            noteTone = Tone.Neutral,
                            metrics = listOf(
                                Metric(
                                    label = R.string.metric_token,
                                    number = outcome.tokenBytes / 1024f,
                                    suffix = R.string.metric_suffix_kb,
                                    decimals = 1,
                                ),
                                Metric(
                                    label = R.string.metric_elapsed,
                                    number = outcome.millis.toFloat(),
                                    suffix = R.string.metric_suffix_ms,
                                    decimals = 0,
                                ),
                            ),
                            action = ScanAction.Rescan,
                            actionEnabled = true,
                            result = r,
                            // Store the facts whenever the verifier hands them back — NOT only
                            // on a clean verdict. A bootstrap that clears the hard gates returns
                            // its ScanSession even when the verdict is REJECT, because the facts
                            // were established from a chain-verified attestation; what failed is
                            // a graded cross-check (a boot-state spoofer, a reused keybox).
                            //
                            // Gating this on r.ok meant a device that grades COMPROMISED could
                            // never carry a session, so every later scan died with no
                            // fingerprint and almost no checks.
                            //
                            // Carrying them launders nothing: the facts include the very flags
                            // that failed, so every steady-state scan re-adjudicates them and
                            // fails the same way.
                            boundSession = r.session ?: it.boundSession,
                        )
                    }
                }
            }
        }
    }

    /**
     * The debug chaos button: leak an anonymous RWX page and drive 50 synthetic
     * scans, then report what the backend half saw. The whole path — button,
     * hook, this function — is compiled out of release builds by the
     * `BuildConfig.DEBUG` guards.
     */
    fun onChaos() {
        if (!BuildConfig.DEBUG) return
        val hook = chaos ?: return
        val bound = _state.value.boundSession
        _state.update {
            it.copy(
                actionEnabled = false,
                note = UiText.of(R.string.note_chaos_running),
                noteTone = Tone.Warn,
            )
        }
        viewModelScope.launch {
            val t0 = android.os.SystemClock.elapsedRealtime()
            val ids = runCatching { hook.run(sessionId, bound) }
                .onFailure { e ->
                    android.util.Log.e("DiSample", "chaos hook threw", e)
                }
                .getOrDefault("(chaos failed)")
            val ms = android.os.SystemClock.elapsedRealtime() - t0
            _state.update {
                it.copy(
                    actionEnabled = true,
                    note = UiText.of(
                        R.string.note_chaos_done,
                        ms,
                        java.lang.Long.toHexString(hook.rwxPage),
                        if (ids.isEmpty()) "(none)" else ids,
                    ),
                    noteTone = Tone.Warn,
                )
            }
        }
    }

    /**
     * Which KIND of scan this was, plus the verifier's reason when it gave one.
     *
     * A steady-state scan legitimately carries less than a bootstrap — no chain, no
     * full fingerprint — and without saying so the second scan looks like it lost
     * checks.
     */
    private fun scanNote(bootstrap: Boolean, reason: String?): UiText {
        val kind = if (bootstrap) R.string.note_bootstrap_scan else R.string.note_steady_scan
        return if (reason == null) {
            UiText.of(kind)
        } else {
            UiText.of(R.string.note_scan_with_reason, UiText.of(kind), reason)
        }
    }
}
