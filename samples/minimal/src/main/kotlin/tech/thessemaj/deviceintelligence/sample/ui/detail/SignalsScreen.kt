package tech.thessemaj.deviceintelligence.sample.ui.detail

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.navigation.Destination
import tech.thessemaj.deviceintelligence.sample.signal.SignalCatalogue
import tech.thessemaj.deviceintelligence.sample.signal.SignalGroup
import tech.thessemaj.deviceintelligence.sample.ui.component.Chip
import tech.thessemaj.deviceintelligence.sample.ui.component.EmptyState
import tech.thessemaj.deviceintelligence.sample.ui.component.Hint
import tech.thessemaj.deviceintelligence.sample.ui.component.KeyValueRow
import tech.thessemaj.deviceintelligence.sample.ui.component.Note
import tech.thessemaj.deviceintelligence.sample.ui.component.IntelCard
import tech.thessemaj.deviceintelligence.sample.ui.component.ScreenScaffold
import tech.thessemaj.deviceintelligence.sample.ui.component.Subhead
import tech.thessemaj.deviceintelligence.sample.ui.component.VSpace
import tech.thessemaj.deviceintelligence.sample.ui.theme.MonoStyle
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.verifier.ResolvedSignal
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.confirmedHookPools
import tech.thessemaj.deviceintelligence.verifier.definitiveHooks

@Composable
fun SignalsScreen(result: ScanResult?, onBack: () -> Unit) {
    ScreenScaffold(
        title = stringResource(R.string.evidence_signals),
        subtitle = stringResource(R.string.evidence_signals_sub),
        onBack = onBack,
        sharedKey = Destination.Signals.route,
    ) {
        if (result == null) {
            EmptyState(stringResource(R.string.empty_no_scan))
            return@ScreenScaffold
        }
        if (result.signals.isEmpty()) {
            Note(stringResource(R.string.signals_none))
            return@ScreenScaffold
        }
        Note(stringResource(R.string.signals_intro))

        // Grouped by family rather than listed flat: a device that is instrumented
        // usually trips several codes from the same detector, and reading them under
        // one heading says "this is one problem" instead of five.
        val byGroup = result.signals.groupBy { SignalCatalogue.of(it.id)?.group }
        SignalGroup.entries.forEach { group ->
            val inGroup = byGroup[group].orEmpty()
            if (inGroup.isNotEmpty()) {
                Subhead(stringResource(group.title), stringResource(group.blurb))
                inGroup.forEach { SignalCard(it) }
            }
        }
        byGroup[null]?.takeIf { it.isNotEmpty() }?.let { unknown ->
            Subhead(
                stringResource(R.string.signal_group_unknown),
                stringResource(R.string.signal_group_unknown_blurb),
            )
            unknown.forEach { SignalCard(it) }
        }

        val confirmed = result.signals.definitiveHooks()
        if (confirmed.isNotEmpty()) {
            Note(stringResource(R.string.signals_definitive_hook, confirmed.joinToString(", ")))
        }
        val pools = result.signals.confirmedHookPools()
        if (pools.isNotEmpty()) {
            Note(stringResource(R.string.signals_confirmed_pools, pools.size))
        }
    }
}

@Composable
private fun SignalCard(s: ResolvedSignal) {
    val colour = if (s.blocking) IntelColors.Red else IntelColors.TextDim
    VSpace(12)
    // The spine encodes severity at a glance on a screen that is often long.
    IntelCard(spine = severityColour(s)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Chip(stringResource(if (s.blocking) R.string.signal_blocking else R.string.signal_info), colour)
            Text(
                text = s.id,
                color = colour,
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                style = MonoStyle,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
        Text(
            stringResource(R.string.signal_meta, s.detector, s.kind, s.severity),
            color = IntelColors.TextDim,
            fontSize = 13.sp,
            modifier = Modifier.padding(top = 6.dp, bottom = 2.dp),
        )
        if (s.title.isNotEmpty()) {
            Text(
                s.title,
                color = Color.White,
                fontSize = 15.sp,
                lineHeight = 21.sp,
                modifier = Modifier.padding(top = 6.dp),
            )
        }

        // What the code means, from the catalogue. The wire carries the code alone.
        val catalogue = SignalCatalogue.of(s.id)
        catalogue?.let { entry ->
            Text(
                stringResource(entry.meaning),
                color = IntelColors.TextDim,
                fontSize = 13.sp,
                lineHeight = 19.sp,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
        prose(s.detail).takeIf { it.isNotEmpty() }?.let {
            Text(
                it,
                color = IntelColors.TextDim,
                fontSize = 13.sp,
                lineHeight = 19.sp,
                modifier = Modifier.padding(top = 10.dp),
            )
        }

        // Every attribute the device attached. This is the enrichment that makes a
        // finding actionable - which module, what it links, which symbol was taken.
        if (s.attributes.isNotEmpty()) {
            Text(
                stringResource(R.string.signal_attached_evidence),
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 14.dp, bottom = 4.dp),
            )
            s.attributes.toSortedMap().forEach { (k, v) -> KeyValueRow(k, v) }
        }
        // The threat capability this finding implies — the "so what" for whoever
        // sets policy. Absent for codes the catalogue has not described yet.
        catalogue?.reach?.let { reach ->
            Text(
                stringResource(R.string.signal_reach_label),
                color = IntelColors.TextDim,
                fontSize = 11.sp,
                modifier = Modifier.padding(top = 14.dp),
            )
            Text(
                stringResource(reach),
                color = IntelColors.Amber,
                fontSize = 13.sp,
                lineHeight = 19.sp,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
        if (catalogue?.retired == true) {
            Hint(stringResource(R.string.signal_retired))
        }
        if (s.isConfirmedHookPool) {
            Hint(stringResource(R.string.signal_hook_pool))
        }
    }
}

/** Blocking outranks severity: policy has already decided this one stops the scan. */
private fun severityColour(s: ResolvedSignal) = when {
    s.blocking -> IntelColors.Red
    s.severity.equals("HIGH", ignoreCase = true) -> IntelColors.Amber
    s.severity.equals("MEDIUM", ignoreCase = true) -> IntelColors.Iris.copy(alpha = 0.6f)
    else -> IntelColors.Stroke
}

/**
 * The human sentence at the front of a detail string.
 *
 * A detail is "a sentence, then key=value tokens the device attached". Those tokens
 * are already resolved into the attributes table below, so leaving them in the prose
 * renders every one twice - and a paragraph that trails off into forty hex digits is
 * unreadable either way.
 */
internal fun prose(detail: String): String {
    val token = Regex("\\s[A-Za-z_][A-Za-z0-9_]*=").find(detail) ?: return detail.trim()
    return detail.substring(0, token.range.first).trim()
}
