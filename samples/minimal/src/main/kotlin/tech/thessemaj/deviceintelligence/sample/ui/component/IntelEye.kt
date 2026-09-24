package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import tech.thessemaj.deviceintelligence.sample.ui.theme.LocalReduceMotion
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors

/**
 * The busy indicator: an ever-present eye, watching.
 *
 * This is the only thing in the app that animates without being asked to, and it
 * only runs while a scan is actually in flight — which is precisely when "something
 * is looking at this device" is the right thing to convey.
 *
 * Goes still, iris open, when the device has animations turned off.
 */
@Composable
fun IntelEye(modifier: Modifier = Modifier) {
    val still = LocalReduceMotion.current
    val transition = rememberInfiniteTransition(label = "eye")

    val sweep by transition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(tween(1900, easing = LinearEasing)),
        label = "sweep",
    )
    // The iris contracts and dilates, the way an eye adjusting to what it sees does.
    val dilation by transition.animateFloat(
        initialValue = 0.72f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1100), repeatMode = RepeatMode.Reverse),
        label = "dilation",
    )

    Canvas(modifier) {
        val r = size.minDimension / 2f
        val centre = Offset(size.width / 2f, size.height / 2f)
        val ring = r - 1.5.dp.toPx()

        drawCircle(IntelColors.Stroke, ring, centre, style = Stroke(1.5.dp.toPx()))
        if (!still) {
            drawArc(
                color = IntelColors.Accent,
                startAngle = sweep,
                sweepAngle = 96f,
                useCenter = false,
                topLeft = Offset(centre.x - ring, centre.y - ring),
                size = Size(ring * 2, ring * 2),
                style = Stroke(1.5.dp.toPx()),
            )
        }
        drawCircle(IntelColors.Iris, ring * 0.46f * (if (still) 1f else dilation), centre)
        drawCircle(IntelColors.Background, ring * 0.18f, centre)
    }
}
