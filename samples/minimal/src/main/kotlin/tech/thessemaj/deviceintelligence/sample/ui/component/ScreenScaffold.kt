package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.animation.core.tween
import io.iamjosephmj.squishy.physics.OverscrollCurve
import io.iamjosephmj.squishy.physics.OverScrollConfig
import io.iamjosephmj.squishy.scroll.OverScrollArea
import io.iamjosephmj.squishy.state.rememberOverScrollState
import io.iamjosephmj.squishy.visual.OverscrollVisuals
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.graphics.Brush
import tech.thessemaj.deviceintelligence.sample.ui.theme.DisplayStyle
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelMark
import tech.thessemaj.deviceintelligence.sample.ui.theme.sharedTitle

/**
 * Every screen in the app: a header that stays put, and content that scrolls
 * under it.
 *
 * The header is pinned rather than scrolled because it carries the only way back.
 * A Back control that scrolls off the top means the way out of a long screen —
 * and the Signals screen IS long — is to scroll all the way up first, or to guess
 * at the system gesture.
 */
@Composable
fun ScreenScaffold(
    title: String,
    subtitle: String? = null,
    onBack: (() -> Unit)? = null,
    /** Shows the mark beside the title. The top-level screen only. */
    showMark: Boolean = false,
    /** Route of the evidence card this screen was opened from, for the shared title. */
    sharedKey: String? = null,
    content: @Composable () -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            // One inset pass for the whole screen. The View implementation had to
            // re-apply this by hand every time it swapped the content view.
            .windowInsetsPadding(WindowInsets.systemBars)
            .padding(20.dp),
    ) {
        HeaderBar(title, subtitle, onBack, showMark, sharedKey)
        val overScrollState = rememberOverScrollState(visual = OverscrollVisuals.pushDown(), config = OverScrollConfig(maxOverscroll = 300f, curve = OverscrollCurve.RubberBand(), settleSpec = tween(300)))
        OverScrollArea(overScrollState) {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                content()
                VSpace(40)
            }
        }
    }
}

/** The shared header: round Back when there is somewhere to go, then the title. */
@Composable
private fun HeaderBar(
    title: String,
    subtitle: String?,
    onBack: (() -> Unit)?,
    showMark: Boolean,
    sharedKey: String?,
) {
    Row(
        Modifier.fillMaxWidth().padding(top = 6.dp, bottom = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (onBack != null) {
            BackButton(onBack)
            HSpace(14)
        }
        if (showMark) {
            IntelMark(Modifier.size(34.dp))
            HSpace(12)
        }
        Column {
            Text(
                title,
                color = Color.White,
                fontSize = 26.sp,
                style = DisplayStyle,
                modifier = if (sharedKey != null) Modifier.sharedTitle(sharedKey) else Modifier,
            )
            if (subtitle != null) {
                Text(
                    subtitle,
                    color = IntelColors.TextDim,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(top = 3.dp),
                )
            }
        }
    }
}

/** A circular control. 52dp across, so it clears the 48dp touch-target floor. */
@Composable
private fun BackButton(onClick: () -> Unit) {
    val label = stringResource(R.string.nav_back)
    Box(
        Modifier
            .size(52.dp)
            .background(IntelColors.Card, CircleShape)
            .border(1.dp, IntelColors.Stroke, CircleShape)
            .clickable(onClick = onClick)
            .semantics { contentDescription = label },
        contentAlignment = Alignment.Center,
    ) {
        Text("‹", color = Color.White, fontSize = 26.sp, textAlign = TextAlign.Center)
    }
}
