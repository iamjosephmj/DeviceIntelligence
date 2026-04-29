package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.DeviceContext
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.ReportSummary
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.TELEMETRY_SCHEMA_VERSION
import io.ssemaj.deviceintelligence.TelemetryReport
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wire-format contract tests for the `integrity.art` detector
 * block in [TelemetryJson]. The encoder is generic — it iterates
 * `report.detectors` and encodes each [DetectorReport] with the
 * same `kvSortedStringMap` machinery — so the goal here is to
 * document and lock the shape backends will receive for every
 * `integrity.art` finding kind, not to test the encoder itself.
 *
 * If a future change renames a detail key or alters severity for
 * one of the `integrity.art` finding kinds, this file's
 * assertions trip first, before the change reaches a backend that
 * depends on the old shape.
 */
class ArtIntegrityTelemetryJsonTest {

    private fun makeReport(findings: List<Finding>): TelemetryReport {
        val detector = DetectorReport(
            id = ArtIntegrityDetector.id,
            status = DetectorStatus.OK,
            durationMs = 1L,
            findings = findings,
        )
        return TelemetryReport(
            schemaVersion = TELEMETRY_SCHEMA_VERSION,
            libraryVersion = "test",
            collectedAtEpochMs = 0L,
            collectionDurationMs = 1L,
            device = DeviceContext(
                manufacturer = "Test",
                model = "Test",
                sdkInt = 36,
                abi = "arm64-v8a",
                fingerprint = "test",
            ),
            app = AppContext(
                packageName = "io.ssemaj.test",
                apkPath = null,
                installerPackage = null,
                signerCertSha256 = emptyList(),
                buildVariant = "debug",
                libraryPluginVersion = "test",
            ),
            detectors = listOf(detector),
            summary = ReportSummary(
                totalFindings = findings.size,
                findingsBySeverity = findings.groupingBy { it.severity }.eachCount(),
                findingsByKind = findings.groupingBy { it.kind }.eachCount(),
                detectorsWithFindings = if (findings.isEmpty()) emptyList() else listOf(detector.id),
                detectorsInconclusive = emptyList(),
                detectorsErrored = emptyList(),
            ),
        )
    }

    @Test
    fun `vector A out_of_range finding serialises with hex addresses`() {
        val finding = Finding(
            kind = ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_OUT_OF_RANGE,
            severity = Severity.HIGH,
            subject = "io.ssemaj.test",
            message = "ArtMethod entry pointer points outside known ART memory regions",
            details = mapOf(
                "method" to "java.lang.Object#hashCode",
                "live_address" to "0xdeadbeef",
                "snapshot_address" to "0x77139d01e0",
                "live_classification" to "unknown",
                "snapshot_classification" to "libart",
            ),
        )
        val json = TelemetryJson.encode(makeReport(listOf(finding)))
        assertTrue("includes detector id", json.contains("\"id\": \"integrity.art\""))
        assertTrue("includes finding kind", json.contains("\"kind\": \"art_method_entry_out_of_range\""))
        assertTrue("includes severity", json.contains("\"severity\": \"high\""))
        assertTrue("hex address preserved", json.contains("\"live_address\": \"0xdeadbeef\""))
        assertTrue("classification surfaced", json.contains("\"snapshot_classification\": \"libart\""))
        // Sorted-key contract: details keys sort alphabetically; "live_address"
        // should come before "method" and "snapshot_address" within the block.
        val detailsBlock = json.substringAfter("\"details\":").substringBefore('}')
        val liveIdx = detailsBlock.indexOf("\"live_address\"")
        val methodIdx = detailsBlock.indexOf("\"method\"")
        val snapIdx = detailsBlock.indexOf("\"snapshot_address\"")
        assertTrue("details sorted: live_address before method", liveIdx in 1..<methodIdx)
        assertTrue("details sorted: method before snapshot_address", methodIdx < snapIdx)
    }

    @Test
    fun `vector C drifted finding includes function name and addresses`() {
        val finding = Finding(
            kind = ArtIntegrityDetector.KIND_JNI_ENV_TABLE_DRIFTED,
            severity = Severity.HIGH,
            subject = "io.ssemaj.test",
            message = "JNIEnv function pointer changed since JNI_OnLoad snapshot",
            details = mapOf(
                "function" to "GetMethodID",
                "live_address" to "0xfeedface",
                "snapshot_address" to "0x77139d01e0",
                "live_classification" to "unknown",
                "snapshot_classification" to "libart",
            ),
        )
        val json = TelemetryJson.encode(makeReport(listOf(finding)))
        assertTrue(json.contains("\"kind\": \"jni_env_table_drifted\""))
        assertTrue(json.contains("\"function\": \"GetMethodID\""))
        assertTrue(json.contains("\"live_address\": \"0xfeedface\""))
    }

    @Test
    fun `vector D drifted finding includes symbol and prologue bytes`() {
        val finding = Finding(
            kind = ArtIntegrityDetector.KIND_ART_INTERNAL_PROLOGUE_DRIFTED,
            severity = Severity.HIGH,
            subject = "io.ssemaj.test",
            message = "ART internal function prologue changed since JNI_OnLoad snapshot",
            details = mapOf(
                "symbol" to "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc",
                "address" to "0x7983633548",
                "live_bytes" to "f0031f04000000d4f0031f04000000d4",
                "snapshot_bytes" to "ff4302d1fd7b05a9f85f06a9f65707a9",
            ),
        )
        val json = TelemetryJson.encode(makeReport(listOf(finding)))
        assertTrue(json.contains("\"kind\": \"art_internal_prologue_drifted\""))
        assertTrue(
            "mangled symbol survives JSON encoding without escapes",
            json.contains("\"symbol\": \"_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc\""),
        )
        assertTrue(json.contains("\"live_bytes\": \"f0031f04000000d4f0031f04000000d4\""))
        assertTrue(
            "summary includes finding kind",
            json.contains("\"art_internal_prologue_drifted\": 1"),
        )
    }

    @Test
    fun `vector D baseline_mismatch finding emits MEDIUM severity`() {
        val finding = Finding(
            kind = ArtIntegrityDetector.KIND_ART_INTERNAL_PROLOGUE_BASELINE_MISMATCH,
            severity = Severity.MEDIUM,
            subject = "io.ssemaj.test",
            message = "ART internal function prologue differs from embedded per-API baseline",
            details = mapOf(
                "symbol" to "JNI_CreateJavaVM",
                "address" to "0x7983be26a0",
                "live_bytes" to "00000000000000000000000000000000",
            ),
        )
        val json = TelemetryJson.encode(makeReport(listOf(finding)))
        assertTrue(json.contains("\"kind\": \"art_internal_prologue_baseline_mismatch\""))
        assertTrue(json.contains("\"severity\": \"medium\""))
        assertTrue(
            "MEDIUM bucket counted in summary",
            json.contains("\"medium\": 1"),
        )
    }

    @Test
    fun `clean integrity_art block serialises with empty findings array`() {
        val json = TelemetryJson.encode(makeReport(emptyList()))
        assertTrue(json.contains("\"id\": \"integrity.art\""))
        assertTrue(json.contains("\"findings\": []"))
        assertTrue(json.contains("\"total_findings\": 0"))
    }
}
