package tech.thessemaj.deviceintelligence.sample.ui.detail

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.navigation.Destination
import tech.thessemaj.deviceintelligence.sample.ui.component.EmptyState
import tech.thessemaj.deviceintelligence.sample.ui.component.Hint
import tech.thessemaj.deviceintelligence.sample.ui.component.KeyValueRow
import tech.thessemaj.deviceintelligence.sample.ui.component.Note
import tech.thessemaj.deviceintelligence.sample.ui.component.ScreenScaffold
import tech.thessemaj.deviceintelligence.sample.ui.component.SectionTable
import tech.thessemaj.deviceintelligence.verifier.ScanResult

@Composable
fun FingerprintScreen(result: ScanResult?, onBack: () -> Unit) {
    ScreenScaffold(
        title = stringResource(R.string.evidence_fingerprint),
        subtitle = stringResource(R.string.evidence_fingerprint_sub),
        onBack = onBack,
        sharedKey = Destination.Fingerprint.route,
    ) {
        if (result == null) {
            EmptyState(stringResource(R.string.empty_no_scan))
            return@ScreenScaffold
        }
        val fp = result.fingerprint
        if (fp == null) {
            Note(stringResource(R.string.fingerprint_absent))
            return@ScreenScaffold
        }
        val unavailable = stringResource(R.string.value_unavailable)

        Note(stringResource(R.string.fingerprint_intro))
        SectionTable(stringResource(R.string.fingerprint_identifiers)) {
            KeyValueRow(stringResource(R.string.fingerprint_device), fp.id ?: unavailable)
            KeyValueRow(stringResource(R.string.fingerprint_app), fp.aid ?: unavailable)
        }
        Hint(stringResource(R.string.fingerprint_device_hint))
        Hint(stringResource(R.string.fingerprint_app_hint))

        SectionTable(stringResource(R.string.fingerprint_platform)) {
            KeyValueRow(stringResource(R.string.fingerprint_widevine), fp.securityLevel ?: unavailable)
            KeyValueRow(stringResource(R.string.fingerprint_kernel), fp.kernel ?: unavailable)
            KeyValueRow(stringResource(R.string.fingerprint_build), fp.build ?: unavailable)
            KeyValueRow(
                stringResource(R.string.fingerprint_patch),
                fp.patch?.let { stringResource(R.string.fingerprint_patch_self_reported, it) }
                    ?: unavailable,
            )
            KeyValueRow(
                stringResource(R.string.fingerprint_installer),
                fp.installer ?: stringResource(R.string.fingerprint_sideloaded),
            )
        }
        Hint(stringResource(R.string.fingerprint_native_hint))
        Note(stringResource(R.string.fingerprint_never_blocks))
    }
}
