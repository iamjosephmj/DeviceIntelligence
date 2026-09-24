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
import tech.thessemaj.deviceintelligence.verifier.ScanSession

@Composable
fun SessionFactsScreen(session: ScanSession?, onBack: () -> Unit) {
    ScreenScaffold(
        title = stringResource(R.string.evidence_session),
        subtitle = stringResource(R.string.evidence_session_sub),
        onBack = onBack,
        sharedKey = Destination.SessionFacts.route,
    ) {
        if (session == null) {
            EmptyState(stringResource(R.string.empty_no_session))
            return@ScreenScaffold
        }
        val notAttested = stringResource(R.string.value_not_attested)

        Note(stringResource(R.string.session_intro))

        SectionTable(stringResource(R.string.session_established)) {
            KeyValueRow(stringResource(R.string.session_assurance), session.assurance.name)
            KeyValueRow(stringResource(R.string.session_boot_state), session.bootState)
            KeyValueRow(stringResource(R.string.session_device_locked), session.deviceLocked.toString())
            KeyValueRow(stringResource(R.string.session_attested_key), session.attestedKey)
            session.attestedApp?.let { app ->
                KeyValueRow(
                    stringResource(R.string.session_attested_app),
                    app.packageNames.joinToString(", "),
                )
                KeyValueRow(
                    stringResource(R.string.session_attested_signer),
                    app.signatureDigests.firstOrNull()
                        ?: stringResource(R.string.session_signer_none),
                )
            }
        }

        SectionTable(stringResource(R.string.session_forensics)) {
            KeyValueRow(stringResource(R.string.session_chain_trusted), session.chainTrusted.toString())
            KeyValueRow(stringResource(R.string.session_keybox_revoked), session.keyboxRevoked.toString())
            KeyValueRow(
                stringResource(R.string.session_cross_level_reuse),
                session.crossLevelReuse.toString(),
            )
            KeyValueRow(
                stringResource(R.string.session_prop_mismatch),
                session.devicePropMismatch.toString(),
            )
            KeyValueRow(
                stringResource(R.string.session_boot_spoofer),
                session.bootStateSpoofer.toString(),
            )
            KeyValueRow(
                stringResource(R.string.session_software_attested),
                session.softwareAttested.toString(),
            )
            KeyValueRow(
                stringResource(R.string.session_strongbox_missing),
                session.strongboxChainMissing.toString(),
            )
        }

        SectionTable(stringResource(R.string.session_patch_levels)) {
            KeyValueRow(stringResource(R.string.session_patch_os), session.osPatchLevel?.toString() ?: notAttested)
            KeyValueRow(
                stringResource(R.string.session_patch_vendor),
                session.vendorPatchLevel?.toString() ?: notAttested,
            )
            KeyValueRow(
                stringResource(R.string.session_patch_boot),
                session.bootPatchLevel?.toString() ?: notAttested,
            )
        }
        Hint(stringResource(R.string.session_staleness_hint))
    }
}
