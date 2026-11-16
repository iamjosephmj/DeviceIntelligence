package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.TextUnit
import tech.thessemaj.deviceintelligence.sample.ui.theme.MonoStyle
import tech.thessemaj.deviceintelligence.sample.ui.theme.Motion
import tech.thessemaj.deviceintelligence.sample.ui.theme.motionDuration

/**
 * A number that settles into place rather than appearing.
 *
 * Used only for the two measured values under the verdict. It reads as an
 * instrument coming to rest, and it costs nothing — the value is already known, the
 * animation just refuses to assert it instantly.
 */
@Composable
fun CountUp(
    target: Float,
    suffix: String,
    decimals: Int,
    colour: Color,
    fontSize: TextUnit,
    modifier: Modifier = Modifier,
) {
    var start by remember { mutableStateOf(false) }
    LaunchedEffect(target) { start = true }
    val value by animateFloatAsState(
        targetValue = if (start) target else 0f,
        animationSpec = tween(motionDuration(Motion.Deliberate), easing = Motion.Enter),
        label = "countUp",
    )
    Text(
        text = "%.${decimals}f".format(value) + suffix,
        color = colour,
        fontSize = fontSize,
        style = MonoStyle,
        modifier = modifier,
    )
}
