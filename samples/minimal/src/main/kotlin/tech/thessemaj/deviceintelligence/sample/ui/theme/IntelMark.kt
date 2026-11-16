package tech.thessemaj.deviceintelligence.sample.ui.theme

import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import tech.thessemaj.deviceintelligence.sample.R

/**
 * The DeviceIntelligence mark, in the app: the snake.
 *
 * Same artwork the launcher icon is built from, so the icon on the home screen
 * and the mark in the header are the same animal. Shipped as a single PNG
 * (`drawable-nodpi/snake_mark.png`) rather than drawn, so there is one source
 * and no drift.
 *
 * The legacy colour parameters are kept so existing call sites compile; the
 * artwork is full-colour and only [alpha] is applied on top.
 */
@Composable
fun IntelMark(
    modifier: Modifier = Modifier,
    ink: Color = IntelColors.Ink,
    muted: Color = IntelColors.InkMuted,
    iris: Color? = IntelColors.Iris,
    alpha: Float = 1f,
) {
    Image(
        painter = painterResource(R.drawable.snake_mark),
        contentDescription = null,
        modifier = modifier,
        alpha = alpha,
        contentScale = ContentScale.Fit,
    )
}
