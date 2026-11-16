package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.ui.scan.Stage
import tech.thessemaj.deviceintelligence.sample.ui.scan.StageState
import tech.thessemaj.deviceintelligence.sample.ui.theme.LocalReduceMotion
import tech.thessemaj.deviceintelligence.sample.ui.theme.MonoStyle
import tech.thessemaj.deviceintelligence.sample.ui.theme.Motion
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.sample.ui.theme.motionDuration

/**
 * `initialize -> setSession -> scan`, drawn.
 *
 * The connector between two stages fills as the later one starts, so the pipeline
 * visibly executes rather than jumping between states — and a failure leaves the
 * rail stopped at the stage that broke, which is the fastest possible answer to
 * "where did this die?".
 */
@Composable
fun PipelineRail(stages: List<Stage>, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        stages.forEachIndexed { index, stage ->
            if (index > 0) {
                Connector(
                    // Filled once the stage on its right has begun.
                    filled = stages[index].state != StageState.Pending,
                    tone = colourFor(stages[index - 1].state),
                    modifier = Modifier.weight(1f).padding(top = 8.dp),
                )
            }
            StageNode(stage)
        }
    }
}

@Composable
private fun Connector(filled: Boolean, tone: Color, modifier: Modifier) {
    val progress by animateFloatAsState(
        targetValue = if (filled) 1f else 0f,
        animationSpec = tween(motionDuration(Motion.Deliberate), easing = Motion.Enter),
        label = "connector",
    )
    Box(
        modifier
            .height(2.dp)
            .background(IntelColors.Stroke, RoundedCornerShape(1.dp)),
    ) {
        Box(
            Modifier
                .fillMaxWidth(progress)
                .fillMaxHeight()
                .background(tone, RoundedCornerShape(1.dp)),
        )
    }
}

@Composable
private fun StageNode(stage: Stage) {
    val target = colourFor(stage.state)
    val colour by animateColorAsState(
        target,
        tween(motionDuration(Motion.Standard)),
        label = "node",
    )

    // A running stage breathes; a settled one is still. The TEE keygen is the slow
    // stage, and this is what says it has not stalled.
    val pulse = if (stage.state == StageState.Running && !LocalReduceMotion.current) {
        val t = rememberInfiniteTransition(label = "pulse")
        val v by t.animateFloat(
            initialValue = 0.72f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(tween(650), repeatMode = RepeatMode.Reverse),
            label = "pulseValue",
        )
        v
    } else {
        1f
    }

    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Box(
            Modifier
                .size(18.dp)
                .scale(pulse)
                .background(IntelColors.Background, CircleShape)
                .padding(3.dp)
                .background(colour, CircleShape),
        )
        Text(
            stringResource(stage.label),
            color = if (stage.state == StageState.Pending) IntelColors.Stroke else IntelColors.TextDim,
            fontSize = 12.sp,
            modifier = Modifier.padding(top = 6.dp),
        )
        Text(
            text = stage.millis?.let { stringResource(R.string.stage_millis, it) } ?: " ",
            color = colour,
            fontSize = 12.sp,
            style = MonoStyle,
        )
    }
}

private fun colourFor(state: StageState): Color = when (state) {
    StageState.Pending -> IntelColors.Stroke
    StageState.Running -> IntelColors.Accent
    StageState.Done -> IntelColors.Green
    StageState.Failed -> IntelColors.Red
}
