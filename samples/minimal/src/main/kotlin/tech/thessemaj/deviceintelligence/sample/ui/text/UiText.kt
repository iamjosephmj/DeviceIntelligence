package tech.thessemaj.deviceintelligence.sample.ui.text

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource

/**
 * Text a ViewModel decides on but only a composable can resolve.
 *
 * The ViewModel picks WHICH sentence applies — that is a decision about the scan —
 * and the screen turns it into characters. Holding a Context in the ViewModel just
 * to format a string would make every state transition untestable off-device, and
 * would put the app's copy somewhere no translator will ever look.
 *
 * Tests assert on the resource id, which is also why they no longer break when
 * someone rewords a sentence.
 */
data class UiText(@StringRes val id: Int, val args: List<Any> = emptyList()) {
    companion object {
        fun of(@StringRes id: Int, vararg args: Any): UiText = UiText(id, args.toList())
    }
}

/**
 * Arguments may themselves be [UiText] — a sentence built from another sentence,
 * such as the scan-kind line followed by the verifier's reason — and are resolved
 * first. Without that, a nested resource id would be formatted as its integer.
 */
@Composable
fun UiText.resolve(): String {
    if (args.isEmpty()) return stringResource(id)
    val resolved = args.map { if (it is UiText) it.resolve() else it }
    return stringResource(id, *resolved.toTypedArray())
}
