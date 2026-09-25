package tech.thessemaj.deviceintelligence.sample.ui.scan
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.PaddingValues
import io.iamjosephmj.flinger.behaviours.FlingPresets
import androidx.compose.animation.core.tween
import io.iamjosephmj.squishy.physics.OverscrollCurve
import io.iamjosephmj.squishy.physics.OverScrollConfig
import io.iamjosephmj.squishy.scroll.OverScrollArea
import io.iamjosephmj.squishy.state.rememberOverScrollState
import io.iamjosephmj.squishy.visual.OverscrollVisuals
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import tech.thessemaj.deviceintelligence.sample.BuildConfig
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.navigation.Destination
import tech.thessemaj.deviceintelligence.sample.ui.component.CountUp
import tech.thessemaj.deviceintelligence.sample.ui.component.PipelineRail
import tech.thessemaj.deviceintelligence.sample.ui.component.IntelEye
import tech.thessemaj.deviceintelligence.sample.ui.theme.DisplayStyle
import tech.thessemaj.deviceintelligence.sample.ui.theme.MonoStyle
import tech.thessemaj.deviceintelligence.sample.ui.theme.Motion
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelMark
import tech.thessemaj.deviceintelligence.sample.ui.theme.sharedTitle
import tech.thessemaj.deviceintelligence.sample.ui.text.resolve
import tech.thessemaj.deviceintelligence.sample.ui.theme.motionDuration
@Composable
fun colourOf(tone: Tone): Color = when (tone) {
    Tone.Neutral -> IntelColors.TextDim
    Tone.Good -> IntelColors.Green
    Tone.Warn -> IntelColors.Amber
    Tone.Bad -> IntelColors.Red
}
/**
 * The instrument panel.
 *
 * Fixed regions top and bottom — the verdict and the pipeline above, the two actions
 * below — with only the evidence scrolling between them. The actions used to sit at
 * the end of one long scroll, which put them off-screen exactly when a scan had
 * found the most to say.
 */
@Composable
fun ScanScreen(
    state: ScanUiState,
    onAction: () -> Unit,
    onOpenDetail: (Destination) -> Unit,
    onChaos: () -> Unit = {},
) {
    Column(
        Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.systemBars)
            .padding(horizontal = 20.dp)
            .padding(top = 20.dp, bottom = 16.dp),
    ) {
        VerdictPanel(state)
        PipelineRail(state.stages, Modifier.padding(top = 22.dp, bottom = 6.dp))
        Evidence(state, onOpenDetail, Modifier.weight(1f))
        ActionButton(state, onAction)
        ChaosButton(state, onChaos)
    }
}

/**
 * The debug red-team control — the ONLY extra affordance on this screen, and
 * absent from release builds entirely: [tech.thessemaj.deviceintelligence.sample.BuildConfig.DEBUG]
 * is a compile-time constant, so both guards fold away.
 *
 * Enabled once a session has scanned, so the sweep runs against an attested
 * steady-state channel exactly as the red-team scenario prescribes.
 */
@Composable
private fun ChaosButton(state: ScanUiState, onChaos: () -> Unit) {
    if (!BuildConfig.DEBUG) return
    androidx.compose.animation.AnimatedVisibility(
        visible = state.action == ScanAction.Rescan && !state.busy,
        enter = fadeIn(),
        exit = fadeOut(),
    ) {
        TextButton(
            onClick = onChaos,
            enabled = state.actionEnabled,
            modifier = Modifier.fillMaxWidth().padding(top = 6.dp),
        ) {
            Text(
                stringResource(R.string.action_chaos),
                color = IntelColors.Amber,
                fontSize = 13.sp,
                style = MonoStyle,
            )
        }
    }
}
@Composable
private fun VerdictPanel(state: ScanUiState) {
    val tone = colourOf(state.verdictTone)
    Row(verticalAlignment = Alignment.Top) {
        IntelMark(Modifier.size(38.dp).padding(top = 4.dp))
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            if (state.busy) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    IntelEye(Modifier.size(24.dp))
                    Text(
                        stringResource(R.string.scan_busy),
                        color = IntelColors.TextDim,
                        fontSize = 15.sp,
                        modifier = Modifier.padding(start = 12.dp),
                    )
                }
            } else {
                Text(
                    text = stringResource(state.verdict ?: R.string.scan_title),
                    color = if (state.verdict == null) Color.White else tone,
                    fontSize = if (state.verdict == null) 30.sp else 36.sp,
                    lineHeight = 40.sp,
                    style = DisplayStyle,
                )
            }
            // The hairline draws itself across, left to right, as the verdict lands.
            key(state.verdict, state.busy) {
                val width by animateFloatAsState(
                    targetValue = if (state.busy) 0f else 1f,
                    animationSpec = tween(motionDuration(Motion.Deliberate), easing = Motion.Enter),
                    label = "rule",
                )
                Box(
                    Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(width)
                        .height(1.dp)
                        .background(
                            Brush.horizontalGradient(
                                listOf(tone.copy(alpha = 0.55f), tone.copy(alpha = 0.05f)),
                            ),
                        ),
                )
            }
            if (state.metrics.isNotEmpty()) {
                Row(Modifier.padding(top = 14.dp)) {
                    state.metrics.forEach { metric ->
                        Column(Modifier.padding(end = 30.dp)) {
                            Text(
                                stringResource(metric.label),
                                color = IntelColors.TextDim,
                                fontSize = 12.sp,
                            )
                            CountUp(
                                target = metric.number,
                                suffix = stringResource(metric.suffix),
                                decimals = metric.decimals,
                                colour = Color.White,
                                fontSize = 20.sp,
                                modifier = Modifier.padding(top = 2.dp),
                            )
                        }
                    }
                }
            }
            state.note?.let { note ->
                Text(
                    text = note.resolve(),
                    color = colourOf(state.noteTone),
                    fontSize = 13.sp,
                    lineHeight = 20.sp,
                    modifier = Modifier.padding(top = 12.dp),
                )
            }
        }
    }
}
/**
 * Evidence, ordered by what is wrong.
 *
 * Anything alarming is promoted to a full-width card at the top; everything quiet
 * collapses into a row of tiles. A rescan that changes the picture moves the cards
 * to their new places rather than swapping them silently, so the reader sees WHICH
 * area became the problem.
 */
@Composable
private fun Evidence(
    state: ScanUiState,
    onOpenDetail: (Destination) -> Unit,
    modifier: Modifier,
) {
    val result = state.result
    if (result == null) {
        Box(modifier.fillMaxWidth())
        return
    }
    val items = remember(result, state.boundSession) { evidenceOf(result, state.boundSession) }
    val promoted = items.filter { it.alarming }
    val quiet = items.filterNot { it.alarming }
    val overScroll = rememberOverScrollState(visual = OverscrollVisuals.pushDown(), config = OverScrollConfig(maxOverscroll = 300f, curve = OverscrollCurve.RubberBand(), settleSpec = tween(300)))
    OverScrollArea(overScroll, modifier) {
    LazyColumn(
        Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        contentPadding = PaddingValues(top = 16.dp, bottom = 16.dp),
        flingBehavior = FlingPresets.iOSStyle(),
    ) {
        itemsIndexed(promoted, key = { _, item -> item.destination.route }) { index, item ->
            // animateItem carries the card to its new slot when a rescan reorders the
            // evidence; Reveal only handles its first appearance.
            Box(Modifier.animateItem()) {
                Reveal(index) { PromotedCard(item) { onOpenDetail(item.destination) } }
            }
        }
        if (quiet.isNotEmpty()) {
            item(key = "tiles") {
                Reveal(promoted.size) {
                    // Intrinsic height so a value that wraps to two lines lifts every
                    // tile with it, rather than leaving the row ragged. Nothing shown
                    // to the reader is clipped or elided.
                    Row(
                        Modifier.height(IntrinsicSize.Min),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        quiet.forEach { item ->
                            QuietTile(item, Modifier.weight(1f).fillMaxHeight()) {
                                onOpenDetail(item.destination)
                            }
                        }
                    }
                }
            }
        }
    }
    }
}
@Composable
private fun PromotedCard(item: EvidenceItem, onClick: () -> Unit) {
    val tone = colourOf(item.tone)
    val shape = RoundedCornerShape(14.dp)
    Row(
        Modifier
            .fillMaxWidth()
            .background(IntelColors.Card, shape)
            .border(1.dp, tone.copy(alpha = 0.35f), shape)
            .clickable(onClick = onClick)
            .padding(18.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                stringResource(item.title),
                color = Color.White,
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.sharedTitle(item.destination.route),
            )
            Text(
                stringResource(item.subtitle),
                color = IntelColors.TextDim,
                fontSize = 13.sp,
                modifier = Modifier.padding(top = 3.dp),
            )
        }
        Text(
            item.summary.resolve(),
            color = tone,
            fontSize = 15.sp,
            style = MonoStyle,
            textAlign = TextAlign.End,
            modifier = Modifier.padding(start = 12.dp, end = 8.dp),
        )
        Text("›", color = IntelColors.TextDim, fontSize = 22.sp)
    }
}
@Composable
private fun QuietTile(item: EvidenceItem, modifier: Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(12.dp)
    Column(
        modifier
            .background(IntelColors.Card, shape)
            .border(1.dp, IntelColors.Stroke, shape)
            .clickable(onClick = onClick)
            .padding(vertical = 14.dp, horizontal = 12.dp),
    ) {
        Text(
            stringResource(item.title).lowercase(),
            color = IntelColors.TextDim,
            fontSize = 11.sp,
        )
        Text(
            item.tileValue.resolve(),
            color = colourOf(item.tone).takeIf { item.tone != Tone.Neutral } ?: Color.White,
            fontSize = 16.sp,
            style = MonoStyle,
            modifier = Modifier.padding(top = 6.dp),
        )
    }
}
@Composable
private fun Reveal(index: Int, content: @Composable () -> Unit) {
    val visible = remember { MutableTransitionState(false) }
    LaunchedEffect(Unit) { visible.targetState = true }
    val duration = motionDuration(Motion.Standard)
    val delay = motionDuration(index * Motion.StaggerStep)
    AnimatedVisibility(
        visibleState = visible,
        enter = fadeIn(tween(duration, delay, Motion.Enter)) +
            slideInVertically(tween(duration, delay, Motion.Enter)) { it / 5 },
    ) { content() }
}
/**
 * The one action.
 *
 * Full width, because there is only ever one thing to do next: initialize, take the
 * first scan, then repeat it. Two half-width buttons meant one of them was always
 * dead, and permanently so once Initialize became one-shot.
 */
@Composable
private fun ActionButton(state: ScanUiState, onAction: () -> Unit) {
    val labelFade = motionDuration(Motion.Quick)
    Button(
        onClick = onAction,
        enabled = state.actionEnabled && !state.busy,
        shape = RoundedCornerShape(14.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = IntelColors.Accent,
            contentColor = Color.White,
            disabledContainerColor = IntelColors.AccentDisabled,
            disabledContentColor = IntelColors.TextDim,
        ),
        modifier = Modifier.fillMaxWidth().height(54.dp),
    ) {
        // Crossfades Initialize -> Scan -> Rescan in place, so it reads as one
        // control advancing rather than three different buttons.
        AnimatedContent(
            targetState = state.action,
            transitionSpec = { fadeIn(tween(labelFade)) togetherWith fadeOut(tween(labelFade)) },
            label = "action",
        ) { action ->
            Text(stringResource(action.label), fontSize = 15.sp, fontWeight = FontWeight.Bold)
        }
    }
}
