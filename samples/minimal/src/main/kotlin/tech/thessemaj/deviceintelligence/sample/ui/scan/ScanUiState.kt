package tech.thessemaj.deviceintelligence.sample.ui.scan

import androidx.annotation.StringRes
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.ui.text.UiText
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.ScanSession

/** Semantic colour, resolved to an actual colour by the composable that draws it. */
enum class Tone { Neutral, Good, Warn, Bad }

/**
 * One labelled number in the readout under the verdict.
 *
 * Kept structured rather than pre-formatted into a sentence so the screen can set
 * the label and the value differently — the value is the thing being read — and so
 * the number can animate up to its target.
 */
data class Metric(
    @StringRes val label: Int,
    val number: Float,
    @StringRes val suffix: Int,
    val decimals: Int,
)

enum class StageState { Pending, Running, Done, Failed }

/**
 * What the one action button does next.
 *
 * There is exactly one thing to do at any point in this flow, so there is exactly
 * one button. It advances through its own lifecycle: initialize the SDK, take the
 * first scan, then repeat it. Two buttons meant one of them was always dead — and
 * once Initialize became one-shot, permanently so.
 */
enum class ScanAction(@StringRes val label: Int) {
    Initialize(R.string.action_initialize),
    Scan(R.string.action_scan),
    Rescan(R.string.action_rescan),
}

/**
 * One stage of `initialize -> setSession -> scan`.
 *
 * The pipeline is the app's actual shape, so the screen draws it rather than
 * describing it in prose. A failure stops the rail visibly at the stage that broke,
 * which used to take a paragraph to work out.
 */
data class Stage(@StringRes val label: Int, val state: StageState, val millis: Long? = null)

private val IDLE_STAGES = listOf(
    Stage(R.string.stage_licence, StageState.Pending),
    Stage(R.string.stage_session, StageState.Pending),
    Stage(R.string.stage_scan, StageState.Pending),
)

data class ScanUiState(
    val stages: List<Stage> = IDLE_STAGES,
    /** The headline word: a verdict after a scan, a status after Initialize. */
    @StringRes val verdict: Int? = null,
    val verdictTone: Tone = Tone.Neutral,
    /** Guidance or the failure reason, under the readout. */
    val note: UiText? = UiText.of(R.string.note_idle),
    val noteTone: Tone = Tone.Neutral,
    val metrics: List<Metric> = emptyList(),
    val action: ScanAction = ScanAction.Initialize,
    val actionEnabled: Boolean = true,
    /** The last verified scan, and the source for every detail screen. */
    val result: ScanResult? = null,
    /** What the backend records for this session; survives across scans. */
    val boundSession: ScanSession? = null,
) {
    val busy: Boolean get() = stages.any { it.state == StageState.Running }


    fun stage(index: Int, state: StageState, millis: Long? = null): List<Stage> =
        stages.mapIndexed { i, s -> if (i == index) s.copy(state = state, millis = millis) else s }

    companion object {
        val IdleStages: List<Stage> = IDLE_STAGES
        const val LICENCE = 0
        const val SESSION = 1
        const val SCAN = 2
    }
}
