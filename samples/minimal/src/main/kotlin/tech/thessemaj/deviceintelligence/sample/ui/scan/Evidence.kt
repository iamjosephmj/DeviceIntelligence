package tech.thessemaj.deviceintelligence.sample.ui.scan

import androidx.annotation.StringRes
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.navigation.Destination
import tech.thessemaj.deviceintelligence.sample.ui.text.UiText
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.ScanSession

/**
 * One area of the evidence, as the scan screen presents it.
 *
 * [alarming] is the whole point of this type: an area with something wrong in it is
 * promoted to a full-width card at the top of the screen, and everything quiet
 * collapses into a compact tile. The screen reshapes around what is wrong instead
 * of presenting the same five rows whatever happened.
 */
data class EvidenceItem(
    val destination: Destination,
    @StringRes val title: Int,
    @StringRes val subtitle: Int,
    /** Full sentence, for the promoted card. */
    val summary: UiText,
    /** Two or three characters, for the tile. */
    val tileValue: UiText,
    val tone: Tone,
    val alarming: Boolean,
    /** Higher sorts first among alarming items. */
    val weight: Int,
)

fun evidenceOf(result: ScanResult, bound: ScanSession?): List<EvidenceItem> {
    val failed = result.checks.count { !it.ok }
    val blocking = result.signals.count { it.blocking }
    val session = result.session ?: bound

    val items = buildList {
        result.attestation?.let { a ->
            add(
                EvidenceItem(
                    destination = Destination.Attestation,
                    title = R.string.evidence_attestation,
                    subtitle = R.string.evidence_attestation_sub,
                    summary = UiText.of(R.string.evidence_attestation_summary, a.level.name, a.reason),
                    tileValue = UiText.of(R.string.value_raw, a.level.name),
                    tone = if (a.degraded) Tone.Warn else Tone.Good,
                    alarming = a.degraded,
                    weight = 80,
                ),
            )
        }
        add(
            EvidenceItem(
                destination = Destination.Checks,
                title = R.string.evidence_checks,
                subtitle = R.string.evidence_checks_sub,
                summary = if (failed == 0) {
                    UiText.of(R.string.evidence_checks_all_passed, result.checks.size)
                } else {
                    UiText.of(R.string.evidence_checks_failed, failed, result.checks.size)
                },
                tileValue = if (failed == 0) {
                    UiText.of(R.string.evidence_checks_tile_ok, result.checks.size)
                } else {
                    UiText.of(R.string.evidence_checks_tile_bad, failed)
                },
                tone = if (failed == 0) Tone.Good else Tone.Bad,
                alarming = failed > 0,
                weight = 90,
            ),
        )
        add(
            EvidenceItem(
                destination = Destination.Signals,
                title = R.string.evidence_signals,
                subtitle = R.string.evidence_signals_sub,
                summary = when {
                    result.signals.isEmpty() -> UiText.of(R.string.evidence_signals_none)
                    blocking == 0 -> UiText.of(R.string.evidence_signals_no_blocking, result.signals.size)
                    else -> UiText.of(R.string.evidence_signals_blocking, result.signals.size, blocking)
                },
                tileValue = if (result.signals.isEmpty()) {
                    UiText.of(R.string.evidence_signals_none)
                } else {
                    UiText.of(R.string.value_count, result.signals.size)
                },
                tone = if (blocking == 0) Tone.Good else Tone.Bad,
                alarming = result.signals.isNotEmpty(),
                weight = 100,
            ),
        )
        add(
            EvidenceItem(
                destination = Destination.Fingerprint,
                title = R.string.evidence_fingerprint,
                subtitle = R.string.evidence_fingerprint_sub,
                summary = result.fingerprint?.securityLevel
                    ?.let { UiText.of(R.string.evidence_fingerprint_widevine, it) }
                    ?: UiText.of(R.string.evidence_fingerprint_absent),
                tileValue = result.fingerprint?.securityLevel
                    ?.let { UiText.of(R.string.value_raw, it) }
                    ?: UiText.of(R.string.value_absent),
                tone = Tone.Neutral,
                // A missing fingerprint never blocks a scan; it is not a problem to raise.
                alarming = false,
                weight = 10,
            ),
        )
        add(
            EvidenceItem(
                destination = Destination.SessionFacts,
                title = R.string.evidence_session,
                subtitle = R.string.evidence_session_sub,
                summary = session?.assurance?.name
                    ?.let { UiText.of(R.string.value_raw, it) }
                    ?: UiText.of(R.string.evidence_session_absent),
                tileValue = session?.assurance?.name
                    ?.let { UiText.of(R.string.value_raw, it) }
                    ?: UiText.of(R.string.value_absent),
                tone = Tone.Neutral,
                alarming = false,
                weight = 20,
            ),
        )
    }
    return items.sortedWith(
        compareByDescending<EvidenceItem> { it.alarming }.thenByDescending { it.weight },
    )
}
