package tech.thessemaj.deviceintelligence.sample.ui.theme

import androidx.compose.foundation.Canvas
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Fill
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.vector.PathParser

/**
 * The DeviceIntelligence mark, in the app.
 *
 * Exactly the geometry the launcher icon is built from — the same path strings,
 * authored in a 512 box — so the bird on the home screen and the bird in the header
 * are the same bird. Drawn rather than shipped as a second asset for the same
 * reason: one source, no drift.
 */
private const val WING = "M152,150 L500,470 C505,475 502,482 495,480 L152,398 Z"
private const val TAIL = "M262,398 L500,470 C505,475 502,482 495,480 L300,452 C285,436 272,418 262,398 Z"
private const val BODY = "M8,84 C8,42 42,8 84,8 C126,8 160,42 160,84 L160,319 C160,361 126,395 84,395 C42,395 8,361 8,319 Z"
private const val BEAK = "M150,36 C202,36 243,58 260,78 C264,83 261,90 254,90 L150,90 Z"
private const val LEG_L = "M100,392 L122,392 L122,464 L100,464 Z"
private const val LEG_R = "M162,392 L184,392 L184,464 L162,464 Z"
private const val FEET = "M76,452 L224,452 A14,14 0 0 1 224,480 L76,480 A14,14 0 0 1 76,452 Z"
private const val EYE = "M82,66 a15,15 0 1,0 30,0 a15,15 0 1,0 -30,0"

/** Source box the paths are authored in. */
private const val SRC_W = 512f
private const val SRC_H = 496f

private fun path(d: String): Path = PathParser().parsePathString(d).toPath()

private class MarkPaths {
    val wing = path(WING)
    val tail = path(TAIL)
    val body = path(BODY)
    val beak = path(BEAK)
    val legL = path(LEG_L)
    val legR = path(LEG_R)
    val feet = path(FEET)
    val eye = path(EYE)
}

/**
 * @param ink the body colour.
 * @param muted wing, beak and legs. Pass the same value as [ink] for a silhouette.
 * @param iris the eye, or null to leave it in [muted] — a ghosted watermark should
 *   not have one bright dot floating in it.
 */
@Composable
fun IntelMark(
    modifier: Modifier = Modifier,
    ink: Color = IntelColors.Ink,
    muted: Color = IntelColors.InkMuted,
    iris: Color? = IntelColors.Iris,
    alpha: Float = 1f,
) {
    val paths = remember { MarkPaths() }
    Canvas(modifier) { drawMark(paths, ink, muted, iris, alpha) }
}

private fun DrawScope.drawMark(
    p: MarkPaths,
    ink: Color,
    muted: Color,
    iris: Color?,
    alpha: Float,
) {
    val s = minOf(size.width / SRC_W, size.height / SRC_H)
    translate((size.width - SRC_W * s) / 2f, (size.height - SRC_H * s) / 2f) {
        scale(s, s, pivot = androidx.compose.ui.geometry.Offset.Zero) {
            drawPath(p.wing, muted, alpha, Fill)
            drawPath(p.tail, muted.copy(alpha = 0.55f), alpha, Fill)
            drawPath(p.body, ink, alpha, Fill)
            drawPath(p.beak, muted, alpha, Fill)
            drawPath(p.legL, muted, alpha, Fill)
            drawPath(p.legR, muted, alpha, Fill)
            drawPath(p.feet, muted, alpha, Fill)
            drawPath(p.eye, iris ?: muted, alpha, Fill)
        }
    }
}
