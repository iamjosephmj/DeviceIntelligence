package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.AttestationReport
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.IntegritySignal
import io.ssemaj.deviceintelligence.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [TelemetryCollector.applyAttestationRuntimeCorrelation]
 * — the CTF Flag 5 derived-finding logic.
 *
 * What we want to lock down:
 *  - The derived finding fires iff `verifiedBootState == "Verified"`
 *    AND there's at least one finding kind mapping to
 *    [IntegritySignal.HOOKING_FRAMEWORK_DETECTED].
 *  - Either condition alone produces no derived finding.
 *  - The derived finding is appended to the `attestation.key`
 *    detector report's findings list, not to the runtime detector
 *    that happened to fire the hook signal.
 *  - The function is idempotent — calling it twice on the same
 *    list with the same app context only emits one derived
 *    finding.
 *  - The `tamper_finding_kinds` detail field captures every
 *    distinct hook-related kind that contributed to the
 *    correlation (sorted, comma-separated for backend parsing
 *    stability).
 */
class AttestationRuntimeCorrelationTest {

    private fun finding(
        kind: String,
        severity: Severity = Severity.HIGH,
        subject: String? = "io.ssemaj.sample",
    ): Finding = Finding(
        kind = kind,
        severity = severity,
        subject = subject,
        message = "test",
        details = emptyMap(),
    )

    private fun report(id: String, findings: List<Finding>): DetectorReport =
        DetectorReport(
            id = id,
            status = DetectorStatus.OK,
            durationMs = 1L,
            findings = findings,
        )

    private fun appWithAttestation(verifiedBootState: String?): AppContext = AppContext(
        packageName = "io.ssemaj.sample",
        apkPath = null,
        installerPackage = null,
        signerCertSha256 = emptyList(),
        buildVariant = null,
        libraryPluginVersion = null,
        attestation = AttestationReport(
            chainB64 = null,
            chainSha256 = "test",
            chainLength = 1,
            attestationSecurityLevel = "StrongBox",
            keymasterSecurityLevel = "StrongBox",
            softwareBacked = false,
            keymasterVersion = null,
            attestationChallengeB64 = null,
            verifiedBootState = verifiedBootState,
            deviceLocked = true,
            verifiedBootKeySha256 = null,
            osVersion = null,
            osPatchLevel = 202604,
            vendorPatchLevel = null,
            bootPatchLevel = null,
            attestedPackageName = "io.ssemaj.sample",
            attestedApplicationIdSha256 = null,
            attestedSignerCertSha256 = emptyList(),
            verdictDeviceRecognition = null,
            verdictAppRecognition = null,
            verdictReason = null,
            verdictAuthoritative = false,
            unavailableReason = null,
        ),
    )

    private fun appWithoutAttestation(): AppContext = AppContext(
        packageName = "io.ssemaj.sample",
        apkPath = null,
        installerPackage = null,
        signerCertSha256 = emptyList(),
        buildVariant = null,
        libraryPluginVersion = null,
        attestation = null,
    )

    private fun derivedFinding(
        reports: List<DetectorReport>,
    ): Finding? = reports
        .firstOrNull { it.id == "attestation.key" }
        ?.findings
        ?.firstOrNull { it.kind == "hardware_attested_but_userspace_tampered" }

    // ---- positive case --------------------------------------------------

    @Test
    fun `verified boot plus hook finding emits derived CRITICAL finding`() {
        val reports = mutableListOf(
            report("attestation.key", listOf(finding("tee_integrity_verdict", Severity.MEDIUM))),
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Verified"),
        )

        val derived = derivedFinding(reports)
        assertNotNull("derived finding must be present", derived)
        assertEquals(Severity.CRITICAL, derived!!.severity)
        assertEquals("io.ssemaj.sample", derived.subject)
        assertEquals("Verified", derived.details["verified_boot_state"])
        assertEquals("hook_framework_present", derived.details["tamper_finding_kinds"])
        assertEquals("1", derived.details["tamper_finding_count"])
    }

    @Test
    fun `multiple distinct hook kinds get joined into details`() {
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.environment", listOf(
                finding("hook_framework_present"),
                finding("rwx_memory_mapping"),
                finding("dex_in_anonymous_mapping"),
            )),
            report("integrity.art", listOf(
                finding("art_method_entry_drifted"),
            )),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Verified"),
        )

        val derived = derivedFinding(reports)!!
        // sorted alphabetically, comma-separated, deduplicated
        assertEquals(
            "art_method_entry_drifted,dex_in_anonymous_mapping,hook_framework_present,rwx_memory_mapping",
            derived.details["tamper_finding_kinds"],
        )
        assertEquals("4", derived.details["tamper_finding_count"])
    }

    @Test
    fun `derived finding is appended to attestation_key, not runtime_environment`() {
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Verified"),
        )

        val attestationFindings = reports.first { it.id == "attestation.key" }.findings
        val runtimeFindings = reports.first { it.id == "runtime.environment" }.findings

        assertEquals(1, attestationFindings.count {
            it.kind == "hardware_attested_but_userspace_tampered"
        })
        assertFalse(
            "derived finding must NOT land on runtime.environment",
            runtimeFindings.any { it.kind == "hardware_attested_but_userspace_tampered" },
        )
        // runtime.environment's original findings are preserved
        assertEquals(1, runtimeFindings.size)
        assertEquals("hook_framework_present", runtimeFindings.single().kind)
    }

    // ---- negative cases -------------------------------------------------

    @Test
    fun `verified boot but no hook findings does not emit derived`() {
        val reports = mutableListOf(
            report("attestation.key", listOf(finding("tee_integrity_verdict", Severity.MEDIUM))),
            // no runtime.environment / integrity.art tampering
            report("runtime.root", listOf(finding("su_binary_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Verified"),
        )

        assertNull(derivedFinding(reports))
    }

    @Test
    fun `hook findings but unverified boot does not emit derived`() {
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Unverified"),
        )

        assertNull(derivedFinding(reports))
    }

    @Test
    fun `null attestation does not emit derived`() {
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithoutAttestation(),
        )

        assertNull(derivedFinding(reports))
    }

    @Test
    fun `verifiedBootState=SelfSigned does not emit derived`() {
        // Only the literal string "Verified" counts. SelfSigned (yellow
        // root-of-trust) means "bootloader unlocked, OS image self-signed
        // by the user" — not the hardware-attested clean state we want
        // to correlate against.
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("SelfSigned"),
        )

        assertNull(derivedFinding(reports))
    }

    @Test
    fun `non-hooking findings do not contribute to the correlation`() {
        // root indicators / emulator / app cloner findings are real
        // tamper signals but conceptually different — the user's device
        // is rooted but no one's actively hooking. Don't escalate to
        // the CRITICAL hardware-attested-tampered finding for those.
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.root", listOf(
                finding("su_binary_present"),
                finding("magisk_artifact_present"),
            )),
            report("runtime.emulator", listOf(finding("running_on_emulator"))),
            report("runtime.cloner", listOf(finding("apk_path_mismatch"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Verified"),
        )

        assertNull(derivedFinding(reports))
    }

    // ---- idempotency ----------------------------------------------------

    @Test
    fun `running correlation twice does not double-emit`() {
        val reports = mutableListOf(
            report("attestation.key", emptyList()),
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )
        val app = appWithAttestation("Verified")

        TelemetryCollector.applyAttestationRuntimeCorrelation(reports, app)
        TelemetryCollector.applyAttestationRuntimeCorrelation(reports, app)

        val attestationFindings = reports.first { it.id == "attestation.key" }.findings
        assertEquals(
            "second call must not emit a duplicate derived finding",
            1,
            attestationFindings.count {
                it.kind == "hardware_attested_but_userspace_tampered"
            },
        )
    }

    // ---- end-to-end signal mapping --------------------------------------

    @Test
    fun `derived finding maps to HARDWARE_ATTESTED_USERSPACE_TAMPERED signal`() {
        val derivedKind = "hardware_attested_but_userspace_tampered"
        val signal = io.ssemaj.deviceintelligence.IntegritySignalMapper.kindToSignal[derivedKind]
        assertEquals(IntegritySignal.HARDWARE_ATTESTED_USERSPACE_TAMPERED, signal)
    }

    @Test
    fun `missing attestation_key detector report is graceful`() {
        // If the detector list was filtered to skip attestation.key
        // (e.g. via CollectOptions.skip), there's no report to append
        // the derived finding to. Function should silently return,
        // not crash.
        val reports = mutableListOf(
            report("runtime.environment", listOf(finding("hook_framework_present"))),
        )

        TelemetryCollector.applyAttestationRuntimeCorrelation(
            reports,
            appWithAttestation("Verified"),
        )

        // No-op — list is unchanged.
        assertEquals(1, reports.size)
        assertEquals(1, reports.single().findings.size)
    }
}
