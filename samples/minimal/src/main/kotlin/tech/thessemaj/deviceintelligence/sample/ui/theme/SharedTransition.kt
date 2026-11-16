package tech.thessemaj.deviceintelligence.sample.ui.theme

import androidx.compose.animation.AnimatedVisibilityScope
import androidx.compose.animation.ExperimentalSharedTransitionApi
import androidx.compose.animation.SharedTransitionScope
import androidx.compose.animation.core.tween
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed

/**
 * Continuity between an evidence card and the screen it opens.
 *
 * The card's title is the same element on both sides, so drilling in reads as that
 * card opening rather than the page being replaced. Passed through composition
 * locals rather than threaded down every screen signature: the scopes are ambient
 * to the navigation graph, and every screen would otherwise carry two parameters it
 * does nothing with.
 */
@OptIn(ExperimentalSharedTransitionApi::class)
val LocalSharedTransitionScope: ProvidableCompositionLocal<SharedTransitionScope?> =
    compositionLocalOf { null }

val LocalNavAnimatedScope: ProvidableCompositionLocal<AnimatedVisibilityScope?> =
    compositionLocalOf { null }

/**
 * Marks this element as the shared title for [key].
 *
 * A no-op when either scope is absent, so the composable stays usable in a preview
 * or a test that has no navigation around it.
 */
@OptIn(ExperimentalSharedTransitionApi::class)
fun Modifier.sharedTitle(key: String): Modifier = composed {
    val shared = LocalSharedTransitionScope.current
    val animated = LocalNavAnimatedScope.current
    val reduceMotion = LocalReduceMotion.current
    if (shared == null || animated == null || reduceMotion) {
        this
    } else {
        with(shared) {
            this@composed.sharedBounds(
                sharedContentState = rememberSharedContentState("title:$key"),
                animatedVisibilityScope = animated,
                boundsTransform = { _, _ -> tween(Motion.Standard, easing = Motion.Enter) },
            )
        }
    }
}
