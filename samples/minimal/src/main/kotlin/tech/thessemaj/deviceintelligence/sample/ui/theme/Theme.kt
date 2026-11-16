package tech.thessemaj.deviceintelligence.sample.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.text.font.DeviceFontFamilyName
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val IntelColorScheme = darkColorScheme(
    background = IntelColors.Background,
    surface = IntelColors.Card,
    surfaceVariant = IntelColors.Card,
    outline = IntelColors.Stroke,
    primary = IntelColors.Accent,
    onPrimary = Color.White,
    onBackground = Color.White,
    onSurface = Color.White,
    onSurfaceVariant = IntelColors.TextDim,
    error = IntelColors.Red,
)

/** Monospace is load-bearing here: ids, digests and hex sessions are read character by character. */
val MonoStyle = TextStyle(fontFamily = FontFamily.Monospace)

/**
 * Condensed grotesque for the verdict and screen titles.
 *
 * Chosen for fit as much as tone: COMPROMISED is eleven characters and has to sit
 * on one line at display size on a 5" phone. Falls back to the platform sans on a
 * device without the condensed family, which costs nothing but width.
 */
val CondensedFamily = FontFamily(
    Font(DeviceFontFamilyName("sans-serif-condensed"), weight = FontWeight.Normal),
    Font(DeviceFontFamilyName("sans-serif-condensed"), weight = FontWeight.Bold),
)

val DisplayStyle = TextStyle(fontFamily = CondensedFamily, fontWeight = FontWeight.Bold)

@Composable
fun DiSampleTheme(
    @Suppress("UNUSED_PARAMETER") darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    // Always the dark scheme — see IntelColors for why this ignores the system setting.
    CompositionLocalProvider(LocalReduceMotion provides rememberReduceMotion()) {
        MaterialTheme(
            colorScheme = IntelColorScheme,
            typography = Typography(),
            content = content,
        )
    }
}
