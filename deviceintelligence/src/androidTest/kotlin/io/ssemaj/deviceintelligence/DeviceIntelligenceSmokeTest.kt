package io.ssemaj.deviceintelligence

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ssemaj.deviceintelligence.internal.NativeBridge
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented smoke suite for [DeviceIntelligence].
 *
 * Validates that `collect()` produces a structurally well-formed
 * report on a real Android runtime — native library loads, every
 * registered detector runs without throwing, summary aggregates are
 * consistent with the underlying detector reports, and the JSON
 * encoding round-trips through `org.json`.
 *
 * **What this suite does NOT assert.** The suite intentionally never
 * asserts "no findings present" — emulators legitimately trip
 * `runtime.emulator` and `integrity.bootloader_unlocked`, AOSP test
 * images expose software-backed key attestation that trips
 * `attestation.key_software_backed`, and dev devices with USB debugging
 * enabled trip `runtime.environment` channels. Asserting empty
 * findings would mean the suite can't run on any realistic surface.
 * Structural correctness is what we validate here; semantic findings
 * are covered by the per-detector unit tests under `src/test/`.
 *
 * Run locally:
 * ```
 * ./gradlew :deviceintelligence:api33DebugAndroidTest
 * ```
 *
 * Run the full API matrix (28/33/35):
 * ```
 * ./gradlew :deviceintelligence:allDevicesDebugAndroidTest
 * ```
 */
@RunWith(AndroidJUnit4::class)
class DeviceIntelligenceSmokeTest {

    private val context: Context get() = ApplicationProvider.getApplicationContext()

    @Test
    fun reportSchemaVersionMatchesConstant() {
        val report = DeviceIntelligence.collectBlocking(context)
        assertEquals(
            "Wire-format contract: schema_version must equal TELEMETRY_SCHEMA_VERSION.",
            TELEMETRY_SCHEMA_VERSION,
            report.schemaVersion,
        )
    }

    @Test
    fun reportLibraryVersionMatchesBuildConfig() {
        val report = DeviceIntelligence.collectBlocking(context)
        assertEquals(
            "TelemetryReport.libraryVersion must match BuildConfig.LIBRARY_VERSION " +
                "(fed from gradle.properties VERSION_NAME).",
            BuildConfig.LIBRARY_VERSION,
            report.libraryVersion,
        )
    }

    @Test
    fun deviceContextPopulatedWithCoreFields() {
        val device = DeviceIntelligence.collectBlocking(context).device
        assertTrue("sdkInt should be >= minSdk (28).", device.sdkInt >= 28)
        assertFalse("Build.MANUFACTURER should be readable on every Android.", device.manufacturer.isEmpty())
        assertFalse("Build.MODEL should be readable on every Android.", device.model.isEmpty())
        assertFalse("Build.FINGERPRINT should be readable on every Android.", device.fingerprint.isEmpty())
        assertFalse("Build.SUPPORTED_ABIS[0] should be non-empty.", device.abi.isEmpty())
    }

    @Test
    fun allRegisteredDetectorsRunByDefault() {
        val report = DeviceIntelligence.collectBlocking(context)
        val ids = report.detectors.map { it.id }.toSet()
        assertEquals(
            "Every registered detector must appear in report.detectors " +
                "under default CollectOptions — absence and 'found nothing' are " +
                "different facts.",
            EXPECTED_DETECTOR_IDS,
            ids,
        )
    }

    @Test
    fun summaryCountsAreConsistentWithDetectorFindings() {
        val report = DeviceIntelligence.collectBlocking(context)
        val findings = report.detectors.flatMap { it.findings }

        assertEquals(
            "summary.totalFindings must equal the sum across detectors.",
            findings.size,
            report.summary.totalFindings,
        )
        assertEquals(
            "summary.findingsBySeverity values must sum to totalFindings.",
            report.summary.totalFindings,
            report.summary.findingsBySeverity.values.sum(),
        )
        assertEquals(
            "summary.findingsByKind values must sum to totalFindings.",
            report.summary.totalFindings,
            report.summary.findingsByKind.values.sum(),
        )

        val detectorsWithNonEmptyFindings = report.detectors
            .filter { it.findings.isNotEmpty() }
            .map { it.id }
            .toSet()
        assertEquals(
            "summary.detectorsWithFindings must mirror detectors whose findings[] is non-empty.",
            detectorsWithNonEmptyFindings,
            report.summary.detectorsWithFindings.toSet(),
        )
    }

    @Test
    fun noDetectorReportedErrorStatus() {
        val report = DeviceIntelligence.collectBlocking(context)
        val errored = report.detectors.filter { it.status == DetectorStatus.ERROR }
        assertTrue(
            "No detector should throw on a vanilla emulator/device — INCONCLUSIVE " +
                "is acceptable (missing data), ERROR means the detector crashed. " +
                "Offenders: " + errored.joinToString { "${it.id} (${it.errorMessage})" },
            errored.isEmpty(),
        )
    }

    @Test
    fun collectJsonProducesParseableObject() {
        val json = DeviceIntelligence.collectJsonBlocking(context)
        assertFalse("collectJson() must return a non-empty string.", json.isEmpty())
        val parsed = JSONObject(json)
        assertEquals(TELEMETRY_SCHEMA_VERSION, parsed.getInt("schema_version"))
        assertEquals(BuildConfig.LIBRARY_VERSION, parsed.getString("library_version"))
        assertNotNull("JSON must carry a device block.", parsed.getJSONObject("device"))
        assertNotNull("JSON must carry an app block.", parsed.getJSONObject("app"))
        assertNotNull("JSON must carry a detectors array.", parsed.getJSONArray("detectors"))
        assertNotNull("JSON must carry a summary block.", parsed.getJSONObject("summary"))
    }

    @Test
    fun collectIsIdempotentAcrossCalls() {
        val first = DeviceIntelligence.collectBlocking(context).detectors.map { it.id }.toSet()
        val second = DeviceIntelligence.collectBlocking(context).detectors.map { it.id }.toSet()
        assertEquals(
            "Two back-to-back collect() calls must produce the same set of " +
                "detector IDs — caching, ordering, and registration are all stable.",
            first,
            second,
        )
    }

    @Test
    fun collectOptionsSkipExcludesNamedDetector() {
        val report = DeviceIntelligence.collectBlocking(
            context,
            CollectOptions(skip = setOf("integrity.apk")),
        )
        val ids = report.detectors.map { it.id }.toSet()
        assertFalse(
            "skip=setOf(\"integrity.apk\") must drop integrity.apk from the report " +
                "(library-only-mode opt-out path).",
            ids.contains("integrity.apk"),
        )
        assertEquals(
            "All other registered detectors must still appear.",
            EXPECTED_DETECTOR_IDS - "integrity.apk",
            ids,
        )
    }

    @Test
    fun collectOptionsOnlyConstrainsToListedDetector() {
        val report = DeviceIntelligence.collectBlocking(
            context,
            CollectOptions(only = setOf("integrity.art")),
        )
        assertEquals(
            "only=setOf(\"integrity.art\") must yield exactly one detector entry — " +
                "the hot-loop observe() use case.",
            setOf("integrity.art"),
            report.detectors.map { it.id }.toSet(),
        )
    }

    @Test
    fun nativeBridgeReportsLibraryLoaded() {
        assertTrue(
            "libdicore.so must load on every supported ABI (arm64-v8a, x86_64, " +
                "armeabi-v7a). isReady() == false here means System.loadLibrary " +
                "failed at NativeBridge static init — a packaging / NDK / ABI " +
                "filter regression.",
            NativeBridge.isReady(),
        )
    }

    private companion object {
        /** Every detector registered by `DeviceIntelligence.collect`. */
        val EXPECTED_DETECTOR_IDS = setOf(
            "integrity.apk",
            "integrity.bootloader",
            "integrity.art",
            "attestation.key",
            "runtime.environment",
            "runtime.root",
            "runtime.emulator",
            "runtime.cloner",
        )
    }
}
