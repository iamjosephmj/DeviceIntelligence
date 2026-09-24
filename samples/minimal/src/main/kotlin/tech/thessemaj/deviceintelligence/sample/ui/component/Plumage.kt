package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.unit.dp
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelMark

/**
 * The ground the whole app sits on: a slow wash from the lit indigo of the mark
 * plumage down to near-black, with the mark ghosted into the bottom corner.
 *
 * Hoisted above the navigation host rather than drawn per screen, so it stays put
 * while screens slide across it — the app has one floor, and moving between screens
 * should not look like moving between rooms.
 *
 * Both the wash and the mark sit far below the contrast of anything readable. This
 * is the surface a verdict is read off; a background that competes with it has
 * failed.
 */
@Composable
fun Plumage(modifier: Modifier = Modifier) {
    Box(
        modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    0f to IntelColors.SheenHigh,
                    0.55f to IntelColors.Background,
                    1f to IntelColors.SheenLow,
                ),
            ),
    ) {
        IntelMark(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .offset(x = 54.dp, y = 40.dp)
                .size(300.dp),
            ink = IntelColors.Ink,
            muted = IntelColors.Ink,
            iris = null,
            alpha = 0.035f,
        )
    }
}
