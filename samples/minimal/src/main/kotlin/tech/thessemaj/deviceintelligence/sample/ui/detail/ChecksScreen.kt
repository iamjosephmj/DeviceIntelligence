package tech.thessemaj.deviceintelligence.sample.ui.detail

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.navigation.Destination
import tech.thessemaj.deviceintelligence.sample.ui.component.CheckRow
import tech.thessemaj.deviceintelligence.sample.ui.component.EmptyState
import tech.thessemaj.deviceintelligence.sample.ui.component.Hint
import tech.thessemaj.deviceintelligence.sample.ui.component.Note
import tech.thessemaj.deviceintelligence.sample.ui.component.ScreenScaffold
import tech.thessemaj.deviceintelligence.sample.ui.component.Subhead
import tech.thessemaj.deviceintelligence.verifier.CheckKind
import tech.thessemaj.deviceintelligence.verifier.ScanResult

@Composable
fun ChecksScreen(result: ScanResult?, onBack: () -> Unit) {
    ScreenScaffold(
        title = stringResource(R.string.evidence_checks),
        subtitle = stringResource(R.string.evidence_checks_sub),
        onBack = onBack,
        sharedKey = Destination.Checks.route,
    ) {
        if (result == null) {
            EmptyState(stringResource(R.string.empty_no_scan))
            return@ScreenScaffold
        }
        Note(stringResource(R.string.checks_intro))

        val auth = result.checks.filter { it.kind == CheckKind.AUTH }
        val integrity = result.checks.filter { it.kind == CheckKind.INTEGRITY }

        if (auth.isNotEmpty()) {
            Subhead(
                stringResource(R.string.checks_authenticity),
                stringResource(R.string.checks_passed_of, auth.count { it.ok }, auth.size),
            )
            auth.forEach { CheckRow(it.ok, it.name, it.detail) }
        }
        if (integrity.isNotEmpty()) {
            Subhead(
                stringResource(R.string.checks_device_integrity),
                stringResource(R.string.checks_passed_of, integrity.count { it.ok }, integrity.size),
            )
            integrity.forEach { CheckRow(it.ok, it.name, it.detail) }
        }
        Hint(stringResource(R.string.checks_order_hint))
    }
}
