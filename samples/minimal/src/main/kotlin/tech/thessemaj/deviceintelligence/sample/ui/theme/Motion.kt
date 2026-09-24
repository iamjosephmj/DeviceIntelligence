package tech.thessemaj.deviceintelligence.sample.ui.theme

import android.provider.Settings
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

/**
 * One motion vocabulary for the whole app.
 *
 * There is a single orchestrated moment here — a scan resolving — and navigation
 * that answers a tap. Nothing animates on its own.
 */
object Motion {
    /** Entrances: decelerate hard, so the result appears to settle rather than drift in. */
    val Enter: Easing = CubicBezierEasing(0.05f, 0.7f, 0.1f, 1f)
    val Exit: Easing = CubicBezierEasing(0.3f, 0f, 0.8f, 0.15f)

    const val Quick = 160
    const val Standard = 280
    const val Deliberate = 420

    /** Gap between consecutive evidence rows as they reveal. */
    const val StaggerStep = 45
}

/**
 * True when the device has animations turned off.
 *
 * Read from the platform's animator duration scale rather than guessed: a tester
 * who has disabled animations to make a flaky UI test deterministic must not get
 * a screen that waits on transitions.
 */
val LocalReduceMotion: ProvidableCompositionLocal<Boolean> = compositionLocalOf { false }

@Composable
fun rememberReduceMotion(): Boolean {
    val resolver = LocalContext.current.contentResolver
    return remember(resolver) {
        Settings.Global.getFloat(resolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) == 0f
    }
}

/** Collapses any duration to zero when the device asks for no motion. */
@Composable
fun motionDuration(millis: Int): Int = if (LocalReduceMotion.current) 0 else millis
