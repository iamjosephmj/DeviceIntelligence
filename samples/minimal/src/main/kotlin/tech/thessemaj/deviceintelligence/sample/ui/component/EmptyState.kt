package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelMark

/**
 * An empty screen is an invitation to act, so this says what to do rather than
 * apologising for having nothing.
 */
@Composable
fun EmptyState(message: String) {
    Column(
        Modifier.fillMaxWidth().padding(top = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        IntelMark(
            modifier = Modifier.size(96.dp),
            ink = IntelColors.InkMuted,
            muted = IntelColors.InkMuted,
            iris = null,
            alpha = 0.5f,
        )
        Note(message, Modifier.padding(top = 20.dp))
    }
}
