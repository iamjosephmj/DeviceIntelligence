package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Calendar
import java.util.TimeZone

/**
 * Pure-JVM unit tests for [deriveIntegrityVerdict].
 *
 * Table-driven: each test exercises one row in the verdict matrix
 * (attestation security level x verified-boot state x device-locked
 * x patch age x F10 status x app-recognition cross-check). The
 * deriver is intentionally a top-level pure function so these
 * tests bring up zero Android infrastructure.
 */
class IntegrityVerdictTest {

    private val now = utcMillis(2026, 4, 28)
    private val recentPatch = 20260301 // ~2 months old
    private val stalePatch = 20240101  // ~2.4 years old
    private val pkg = "com.example.app"
    private val signerHex = "ab".repeat(32) // 64 hex chars

    @Test
    fun `full pass is LOW with all three tiers and RECOGNIZED`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(
            setOf(
                DeviceTier.MEETS_BASIC_INTEGRITY,
                DeviceTier.MEETS_DEVICE_INTEGRITY,
                DeviceTier.MEETS_STRONG_INTEGRITY,
            ),
            v.deviceRecognition,
        )
        assertEquals(AppRecognition.RECOGNIZED, v.appRecognition)
        assertEquals(Severity.LOW, v.severity)
        assertNull(v.reason)
    }

    @Test
    fun `stale patch downgrades from STRONG to DEVICE with MEDIUM and patch_too_old`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = stalePatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(
            setOf(
                DeviceTier.MEETS_BASIC_INTEGRITY,
                DeviceTier.MEETS_DEVICE_INTEGRITY,
            ),
            v.deviceRecognition,
        )
        assertEquals(AppRecognition.RECOGNIZED, v.appRecognition)
        assertEquals(Severity.MEDIUM, v.severity)
        assertEquals("patch_too_old", v.reason)
    }

    @Test
    fun `unlocked bootloader downgrades to DEVICE with MEDIUM and bootloader_unlocked`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = false,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(
            setOf(
                DeviceTier.MEETS_BASIC_INTEGRITY,
                DeviceTier.MEETS_DEVICE_INTEGRITY,
            ),
            v.deviceRecognition,
        )
        assertEquals(Severity.MEDIUM, v.severity)
        assertEquals("bootloader_unlocked", v.reason)
    }

    @Test
    fun `self-signed boot state qualifies for DEVICE but not STRONG`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            verifiedBootState = VerifiedBootState.SELF_SIGNED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(
            setOf(
                DeviceTier.MEETS_BASIC_INTEGRITY,
                DeviceTier.MEETS_DEVICE_INTEGRITY,
            ),
            v.deviceRecognition,
        )
        assertEquals(Severity.MEDIUM, v.severity)
        assertEquals("boot_self_signed", v.reason)
    }

    @Test
    fun `unverified boot state stops at BASIC with HIGH and boot_unverified`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            verifiedBootState = VerifiedBootState.UNVERIFIED,
            deviceLocked = false,
            osPatchLevel = stalePatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(setOf(DeviceTier.MEETS_BASIC_INTEGRITY), v.deviceRecognition)
        assertEquals(Severity.HIGH, v.severity)
        assertEquals("boot_unverified", v.reason)
    }

    @Test
    fun `software-only attestation produces empty tier set with CRITICAL`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.SOFTWARE,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(emptySet<DeviceTier>(), v.deviceRecognition)
        assertEquals(Severity.CRITICAL, v.severity)
        assertEquals("software_attestation", v.reason)
    }

    @Test
    fun `null parsed yields UNEVALUATED with key_description_unparseable`() {
        val v = deriveIntegrityVerdict(
            parsed = null,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(emptySet<DeviceTier>(), v.deviceRecognition)
        assertEquals(AppRecognition.UNEVALUATED, v.appRecognition)
        assertEquals(Severity.CRITICAL, v.severity)
        assertEquals("key_description_unparseable", v.reason)
    }

    @Test
    fun `F10 with findings produces UNRECOGNIZED_VERSION and CRITICAL`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )
        val f10 = okF10(
            listOf(
                Finding(
                    kind = "apk_entry_modified",
                    severity = Severity.CRITICAL,
                    subject = "classes.dex",
                    message = "tampered",
                    details = emptyMap(),
                ),
            ),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = f10,
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(AppRecognition.UNRECOGNIZED_VERSION, v.appRecognition)
        // Device side is fine, but app-side mismatch escalates to CRITICAL.
        assertEquals(Severity.CRITICAL, v.severity)
        assertEquals("app_identity_mismatch", v.reason)
    }

    @Test
    fun `F10 inconclusive produces UNEVALUATED app recognition`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )
        val f10 = DetectorReport(
            id = "F10.apk_integrity",
            status = DetectorStatus.INCONCLUSIVE,
            durationMs = 1,
            findings = emptyList(),
            inconclusiveReason = "apk_unreadable",
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = f10,
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(AppRecognition.UNEVALUATED, v.appRecognition)
        // Device side is clean — severity stays LOW.
        assertEquals(Severity.LOW, v.severity)
    }

    @Test
    fun `attested package mismatch is UNRECOGNIZED_VERSION`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = "com.attacker.spoof",
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(AppRecognition.UNRECOGNIZED_VERSION, v.appRecognition)
        assertEquals(Severity.CRITICAL, v.severity)
    }

    @Test
    fun `attested signer not in runtime set is UNRECOGNIZED_VERSION`() {
        val attackerSigner = "ff".repeat(32)
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(attackerSigner),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(AppRecognition.UNRECOGNIZED_VERSION, v.appRecognition)
        assertEquals(Severity.CRITICAL, v.severity)
    }

    @Test
    fun `no attested signers leaves recognition UNEVALUATED, not UNRECOGNIZED`() {
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = emptyList(),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        assertEquals(AppRecognition.UNEVALUATED, v.appRecognition)
        // No app downgrade — device tier is full pass, severity stays LOW.
        assertEquals(Severity.LOW, v.severity)
    }

    @Test
    fun `KeyMaster 4 YYYYMM patch level encoding accepted`() {
        // Patch level encoded as YYYYMM (no day) on KM 4 — promote to first.
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = 202603, // YYYYMM form
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(signerHex),
            nowEpochMs = now,
        )

        // Still recent enough for STRONG.
        assertEquals(
            setOf(
                DeviceTier.MEETS_BASIC_INTEGRITY,
                DeviceTier.MEETS_DEVICE_INTEGRITY,
                DeviceTier.MEETS_STRONG_INTEGRITY,
            ),
            v.deviceRecognition,
        )
    }

    @Test
    fun `signer comparison is case-insensitive`() {
        val mixed = signerHex.uppercase()
        val parsed = parsedKeyDescription(
            securityLevel = SecurityLevel.STRONG_BOX,
            verifiedBootState = VerifiedBootState.VERIFIED,
            deviceLocked = true,
            osPatchLevel = recentPatch,
            attestedPackageName = pkg,
            attestedSignerDigestsHex = listOf(signerHex),
        )

        val v = deriveIntegrityVerdict(
            parsed = parsed,
            f10Report = okF10(emptyList()),
            runtimePackageName = pkg,
            runtimeSignerCertSha256 = listOf(mixed),
            nowEpochMs = now,
        )

        assertEquals(AppRecognition.RECOGNIZED, v.appRecognition)
    }

    // ---- helpers -----------------------------------------------------------

    private fun parsedKeyDescription(
        securityLevel: SecurityLevel,
        verifiedBootState: VerifiedBootState?,
        deviceLocked: Boolean?,
        osPatchLevel: Int?,
        attestedPackageName: String?,
        attestedSignerDigestsHex: List<String>,
    ): ParsedKeyDescription = ParsedKeyDescription(
        attestationVersion = 4,
        attestationSecurityLevel = securityLevel,
        keymasterVersion = 41,
        keymasterSecurityLevel = securityLevel,
        attestationChallenge = ByteArray(0),
        verifiedBootState = verifiedBootState,
        deviceLocked = deviceLocked,
        verifiedBootKey = null,
        osVersion = null,
        osPatchLevel = osPatchLevel,
        vendorPatchLevel = null,
        bootPatchLevel = null,
        attestedPackageName = attestedPackageName,
        attestationApplicationIdRaw = null,
        attestedSignerDigestsHex = attestedSignerDigestsHex,
    )

    private fun okF10(findings: List<Finding>): DetectorReport = DetectorReport(
        id = "F10.apk_integrity",
        status = DetectorStatus.OK,
        durationMs = 1,
        findings = findings,
    )

    private fun utcMillis(year: Int, monthOneBased: Int, day: Int): Long {
        val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        cal.clear()
        cal.set(year, monthOneBased - 1, day, 0, 0, 0)
        return cal.timeInMillis
    }
}
