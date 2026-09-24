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
import tech.thessemaj.deviceintelligence.sample.ui.component.Subhead
import tech.thessemaj.deviceintelligence.verifier.TokenAttestation

@Composable
fun AttestationScreen(attestation: TokenAttestation?, onBack: () -> Unit) {
    ScreenScaffold(
        title = stringResource(R.string.evidence_attestation),
        subtitle = stringResource(R.string.evidence_attestation_sub),
        onBack = onBack,
        sharedKey = Destination.Attestation.route,
    ) {
        if (attestation == null) {
            EmptyState(stringResource(R.string.empty_no_scan))
            return@ScreenScaffold
        }

        Note(
            stringResource(
                if (attestation.degraded) {
                    R.string.attestation_degraded_intro
                } else {
                    R.string.attestation_bound_intro
                },
            ),
        )

        SectionTable(stringResource(R.string.attestation_claim)) {
            KeyValueRow(stringResource(R.string.attestation_key), attestation.level.name)
            KeyValueRow(stringResource(R.string.attestation_signed_by), attestation.signed.name)
            KeyValueRow(stringResource(R.string.attestation_reason), attestation.reason)
            KeyValueRow(
                stringResource(R.string.attestation_detail),
                attestation.detail ?: stringResource(R.string.value_none_reported),
            )
        }
        Hint(stringResource(R.string.attestation_key_hint))

        if (attestation.degraded) {
            Subhead(
                stringResource(R.string.attestation_bug_or_injection),
                stringResource(R.string.attestation_bug_or_injection_why),
            )
            Hint(stringResource(R.string.attestation_axis_reason))
            Hint(stringResource(R.string.attestation_axis_corroboration))
            Note(stringResource(R.string.attestation_self_reported))
        }
    }
}
