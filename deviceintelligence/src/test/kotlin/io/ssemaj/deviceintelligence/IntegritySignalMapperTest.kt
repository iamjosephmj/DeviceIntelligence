package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM contract tests for [IntegritySignalMapper] and the
 * [IntegritySignal] vocabulary.
 *
 * Two things this file pins:
 *
 *  1. The kind → signal mapping for every kind the library
 *     currently emits. If a detector adds a new kind without a
 *     corresponding entry in `KIND_TO_SIGNAL`, [mapping_table_covers_every_known_kind]
 *     will fail (or the kind will fall through to `unmappedFindings`,
 *     caught by the per-detector tests).
 *  2. The semantics of the wrapper — empty input returns
 *     [IntegritySignalReport.EMPTY], multiple findings of the same
 *     kind collapse to a single signal, and unrecognised kinds are
 *     surfaced rather than dropped.
 */
class IntegritySignalMapperTest {

    @Test
    fun `empty report yields no signals and no evidence`() {
        val report = makeReport(emptyList())
        val signals = report.toIntegritySignals()
        val full = report.toIntegritySignalReport()

        assertTrue("signals empty", signals.isEmpty())
        assertSame("empty fast-path returns EMPTY singleton", IntegritySignalReport.EMPTY, full)
        assertTrue(full.signals.isEmpty())
        assertTrue(full.evidence.isEmpty())
        assertTrue(full.unmappedFindings.isEmpty())
    }

    @Test
    fun `report with only unmapped findings still returns a non-EMPTY report`() {
        val unknownFinding = makeFinding(kind = "totally_made_up_kind_v999", subject = "foo")
        val report = makeReport(
            listOf(makeDetector(id = "runtime.future", findings = listOf(unknownFinding))),
        )

        val mapped = report.toIntegritySignalReport()

        assertTrue("no signals", mapped.signals.isEmpty())
        assertTrue("no evidence", mapped.evidence.isEmpty())
        assertEquals("unknown kind surfaced", listOf(unknownFinding), mapped.unmappedFindings)
    }

    @Test
    fun `multiple findings of the same kind collapse to one signal`() {
        val findings = listOf(
            makeFinding(kind = "su_binary_present", subject = "/system/xbin/su"),
            makeFinding(kind = "su_binary_present", subject = "/sbin/su"),
            makeFinding(kind = "magisk_artifact_present", subject = "/sbin/.magisk"),
        )
        val report = makeReport(
            listOf(makeDetector(id = "runtime.root", findings = findings)),
        )

        val mapped = report.toIntegritySignalReport()

        assertEquals(setOf(IntegritySignal.ROOT_INDICATORS_PRESENT), mapped.signals)
        assertEquals(
            "all 3 findings attributed to the single signal",
            findings,
            mapped.evidence[IntegritySignal.ROOT_INDICATORS_PRESENT],
        )
        assertTrue(mapped.unmappedFindings.isEmpty())
    }

    @Test
    fun `findings across different detectors fold into independent signals`() {
        val report = makeReport(
            listOf(
                makeDetector(
                    id = "integrity.apk",
                    findings = listOf(makeFinding(kind = "apk_signer_mismatch")),
                ),
                makeDetector(
                    id = "runtime.environment",
                    findings = listOf(
                        makeFinding(kind = "stack_foreign_frame"),
                        makeFinding(kind = "rwx_memory_mapping"),
                    ),
                ),
                makeDetector(
                    id = "runtime.root",
                    findings = listOf(makeFinding(kind = "magisk_artifact_present")),
                ),
            ),
        )

        val signals = report.toIntegritySignals()

        assertEquals(
            setOf(
                IntegritySignal.APK_TAMPERED,
                IntegritySignal.HOOKING_FRAMEWORK_DETECTED,
                IntegritySignal.ROOT_INDICATORS_PRESENT,
            ),
            signals,
        )
    }

    @Test
    fun `signalsOf returns same signals as the full report`() {
        val report = makeReport(
            listOf(
                makeDetector(
                    id = "runtime.environment",
                    findings = listOf(
                        makeFinding(kind = "debugger_attached"),
                        makeFinding(kind = "ro_debuggable_mismatch"),
                        makeFinding(kind = "injected_library"),
                    ),
                ),
            ),
        )

        val viaSignals = IntegritySignalMapper.signalsOf(report)
        val viaReport = IntegritySignalMapper.report(report).signals

        assertEquals(viaSignals, viaReport)
        assertEquals(
            setOf(
                IntegritySignal.DEBUGGER_ATTACHED,
                IntegritySignal.DEBUG_FLAG_MISMATCH,
                IntegritySignal.INJECTED_NATIVE_CODE,
            ),
            viaSignals,
        )
    }

    @Test
    fun `mixed mapped and unmapped findings preserves both views`() {
        val knownFinding = makeFinding(kind = "running_on_emulator", subject = "abi:x86_64")
        val unknownFinding = makeFinding(kind = "future_only_kind", subject = "future")
        val report = makeReport(
            listOf(
                makeDetector(
                    id = "runtime.emulator",
                    findings = listOf(knownFinding, unknownFinding),
                ),
            ),
        )

        val mapped = report.toIntegritySignalReport()

        assertEquals(setOf(IntegritySignal.EMULATOR_DETECTED), mapped.signals)
        assertEquals(
            listOf(knownFinding),
            mapped.evidence[IntegritySignal.EMULATOR_DETECTED],
        )
        assertEquals(listOf(unknownFinding), mapped.unmappedFindings)
    }

    @Test
    fun `every kind in KIND_TO_SIGNAL maps to a non-null signal`() {
        for ((kind, signal) in IntegritySignalMapper.kindToSignal) {
            assertNotNull("kind '$kind' must map to a signal", signal)
        }
    }

    @Test
    fun `mapping table covers every kind currently emitted by detectors`() {
        // This is the canonical wire-format vocabulary the library
        // emits today. If a new finding kind is added to a detector
        // without a corresponding entry in KIND_TO_SIGNAL, this test
        // fails — that's the safety net.
        //
        // Order roughly mirrors the detectors:
        //   integrity.apk · integrity.bootloader · integrity.art ·
        //   attestation.key · runtime.environment · runtime.root ·
        //   runtime.emulator · runtime.cloner.
        val expectedKinds = setOf(
            // integrity.apk
            "apk_signer_mismatch",
            "apk_source_dir_unexpected",
            "installer_not_whitelisted",
            "apk_entry_removed",
            "apk_entry_modified",
            "apk_entry_added",
            "fingerprint_asset_missing",
            "fingerprint_key_missing",
            "fingerprint_bad_magic",
            "fingerprint_corrupt",
            // integrity.bootloader
            "bootloader_integrity_anomaly",
            "bootloader_strongbox_unavailable",
            // attestation.key
            "tee_integrity_verdict",
            // integrity.art (15 kinds)
            "art_method_entry_out_of_range",
            "art_method_entry_drifted",
            "art_baseline_tampered",
            "jni_env_table_out_of_range",
            "jni_env_table_drifted",
            "jni_env_baseline_tampered",
            "art_internal_prologue_drifted",
            "art_internal_prologue_baseline_mismatch",
            "art_internal_prologue_baseline_tampered",
            "art_method_jni_entry_drifted",
            "art_method_jni_entry_out_of_range",
            "art_method_jni_entry_baseline_tampered",
            "art_method_acc_native_flipped_on",
            "art_method_acc_native_flipped_off",
            "art_method_access_flags_baseline_tampered",
            // runtime.environment + native integrity (G2-G7)
            "debugger_attached",
            "ro_debuggable_mismatch",
            "hook_framework_present",
            "rwx_memory_mapping",
            "stack_foreign_frame",
            "native_caller_out_of_range",
            "native_text_hash_mismatch",
            "native_text_drifted",
            "got_entry_drifted",
            "got_entry_out_of_range",
            "injected_library",
            "injected_anonymous_executable",
            // Frida 16+ memfd-JIT attribution (parallel to the
            // generic hook_framework_present; both map to
            // HOOKING_FRAMEWORK_DETECTED)
            "frida_memfd_jit_present",
            // CTF Flag 1 — DEX injection (emitted by DexInjection
            // helper inside runtime.environment, NOT a separate detector)
            "dex_classloader_added",
            "dex_path_outside_apk",
            "dex_in_memory_loader_injected",
            "dex_in_anonymous_mapping",
            "unattributable_dex_at_baseline",
            // runtime.root
            "su_binary_present",
            "magisk_artifact_present",
            "test_keys_build",
            "which_su_succeeded",
            "root_manager_app_installed",
            // runtime.root — Shamiko-bypass channels (1.x additive)
            "magisk_in_init_mountinfo",
            "magisk_daemon_socket_present",
            "tls_trust_store_tampered",
            // runtime.emulator
            "running_on_emulator",
            // runtime.cloner
            "apk_path_mismatch",
            "data_dir_mount_invalid",
            "uid_mismatch",
            // CTF Flag 5 — attestation × runtime correlation
            "hardware_attested_but_userspace_tampered",
            // attestation.key — CBOR/EAT format detection (KeyMint 200+ / 1.x additive)
            "attestation_eat_format_detected",
        )
        val mappedKinds = IntegritySignalMapper.kindToSignal.keys
        val missing = expectedKinds - mappedKinds
        val extra = mappedKinds - expectedKinds
        assertTrue(
            "kinds emitted by detectors but not in mapping table: $missing",
            missing.isEmpty(),
        )
        assertTrue(
            "kinds in mapping table but not in expected vocabulary " +
                "(stale entry?): $extra",
            extra.isEmpty(),
        )
    }

    @Test
    fun `signal-by-signal smoke test exercises every enum value`() {
        // For each signal, pick one canonical kind that maps to it
        // and verify the mapping. Catches accidental rewires.
        val canonical: Map<IntegritySignal, String> = mapOf(
            IntegritySignal.APK_TAMPERED to "apk_entry_modified",
            IntegritySignal.APK_FINGERPRINT_UNAVAILABLE to "fingerprint_asset_missing",
            IntegritySignal.BOOTLOADER_INTEGRITY_FAILED to "bootloader_integrity_anomaly",
            IntegritySignal.TEE_ATTESTATION_DEGRADED to "tee_integrity_verdict",
            IntegritySignal.HOOKING_FRAMEWORK_DETECTED to "stack_foreign_frame",
            IntegritySignal.INJECTED_NATIVE_CODE to "injected_library",
            IntegritySignal.ROOT_INDICATORS_PRESENT to "su_binary_present",
            IntegritySignal.EMULATOR_DETECTED to "running_on_emulator",
            IntegritySignal.APP_CLONED to "data_dir_mount_invalid",
            IntegritySignal.DEBUGGER_ATTACHED to "debugger_attached",
            IntegritySignal.DEBUG_FLAG_MISMATCH to "ro_debuggable_mismatch",
            IntegritySignal.HARDWARE_ATTESTED_USERSPACE_TAMPERED to
                "hardware_attested_but_userspace_tampered",
        )
        // Sanity-check we covered every enum value.
        assertEquals(
            "canonical map must cover every IntegritySignal",
            IntegritySignal.values().toSet(),
            canonical.keys,
        )
        for ((expectedSignal, kind) in canonical) {
            val report = makeReport(
                listOf(makeDetector("test", listOf(makeFinding(kind = kind)))),
            )
            assertEquals(
                "kind '$kind' must map to $expectedSignal",
                setOf(expectedSignal),
                report.toIntegritySignals(),
            )
        }
    }

    @Test
    fun `EMPTY companion is the same instance returned for empty inputs`() {
        val viaConstructor = IntegritySignalReport.EMPTY
        val viaEmptyReport = makeReport(emptyList()).toIntegritySignalReport()
        assertSame(viaConstructor, viaEmptyReport)
        assertEquals(emptySet<IntegritySignal>(), viaConstructor.signals)
    }

    @Test
    fun `unrecognised kind does not raise a signal even if detector produced findings`() {
        val report = makeReport(
            listOf(
                makeDetector(
                    "runtime.future",
                    listOf(makeFinding(kind = "brand_new_kind")),
                ),
            ),
        )
        assertTrue(report.toIntegritySignals().isEmpty())
        assertNull(report.toIntegritySignalReport().evidence[IntegritySignal.HOOKING_FRAMEWORK_DETECTED])
    }

    // ---- helpers --------------------------------------------------------

    private fun makeReport(detectors: List<DetectorReport>): TelemetryReport =
        TelemetryReport(
            schemaVersion = TELEMETRY_SCHEMA_VERSION,
            libraryVersion = "test",
            collectedAtEpochMs = 0L,
            collectionDurationMs = 0L,
            device = DeviceContext(
                manufacturer = "test",
                model = "test",
                sdkInt = 28,
                abi = "arm64-v8a",
                fingerprint = "test/fingerprint",
            ),
            app = AppContext(
                packageName = "io.ssemaj.test",
                apkPath = null,
                installerPackage = null,
                signerCertSha256 = emptyList(),
                buildVariant = null,
                libraryPluginVersion = null,
            ),
            detectors = detectors,
            summary = ReportSummary(
                totalFindings = detectors.sumOf { it.findings.size },
                findingsBySeverity = emptyMap(),
                findingsByKind = emptyMap(),
                detectorsWithFindings = detectors.filter { it.findings.isNotEmpty() }.map { it.id },
                detectorsInconclusive = emptyList(),
                detectorsErrored = emptyList(),
            ),
        )

    private fun makeDetector(
        id: String,
        findings: List<Finding>,
    ): DetectorReport = DetectorReport(
        id = id,
        status = DetectorStatus.OK,
        durationMs = 0L,
        findings = findings,
    )

    private fun makeFinding(
        kind: String,
        severity: Severity = Severity.HIGH,
        subject: String? = null,
    ): Finding = Finding(
        kind = kind,
        severity = severity,
        subject = subject,
        message = "test finding $kind",
        details = emptyMap(),
    )
}
