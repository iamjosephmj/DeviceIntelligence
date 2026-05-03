package io.ssemaj.deviceintelligence

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [SessionFindingsAggregator] and the
 * [DeviceIntelligence.observeSessionFlow] wrapper.
 *
 * What we lock down:
 *  - Identity is `(detectorId, kind, subject)`. Message / details
 *    drift does NOT shift identity.
 *  - First-seen / last-seen / observation counts increment correctly
 *    across multiple ingests.
 *  - `stillActive` flips off when a finding disappears from the
 *    latest report, and back on if the same finding re-appears.
 *  - Disappeared findings are NOT dropped — they stay in the list
 *    so consumer UIs can render historical evidence.
 *  - The Flow wrapper builds a fresh aggregator per `collect()` so
 *    two collectors of the same returned Flow get independent
 *    sessions.
 *
 * Stub report builder lifted from `ObserveFlowTest` (same shape;
 * could share via a fixture file but the duplication is small).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SessionFindingsTest {

    // ---- helpers --------------------------------------------------------

    private fun stubReport(
        collectedAtEpochMs: Long,
        detectors: List<DetectorReport>,
    ): TelemetryReport = TelemetryReport(
        schemaVersion = TELEMETRY_SCHEMA_VERSION,
        libraryVersion = "test",
        collectedAtEpochMs = collectedAtEpochMs,
        collectionDurationMs = 0L,
        device = DeviceContext(
            manufacturer = "test",
            model = "stub",
            sdkInt = 0,
            abi = "x86_64",
            fingerprint = "stub",
        ),
        app = AppContext(
            packageName = "test",
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

    private fun stubFinding(
        kind: String,
        subject: String? = null,
        message: String = "msg",
        severity: Severity = Severity.MEDIUM,
        details: Map<String, String> = emptyMap(),
    ): Finding = Finding(
        kind = kind,
        severity = severity,
        subject = subject,
        message = message,
        details = details,
    )

    private fun stubDetector(id: String, findings: List<Finding>): DetectorReport =
        DetectorReport(
            id = id,
            status = DetectorStatus.OK,
            durationMs = 1L,
            findings = findings,
        )

    // ---- identity contract ---------------------------------------------

    @Test
    fun `identityKey collapses same detector kind subject`() {
        val a = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "hook_framework_present", subject = "frida"),
        )
        val b = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "hook_framework_present", subject = "frida", message = "different message"),
        )
        assertEquals("message difference must not shift identity", a, b)
    }

    @Test
    fun `identityKey distinguishes by detector id`() {
        val a = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "hook_framework_present", subject = "frida"),
        )
        val b = SessionFindingsAggregator.identityKey(
            "integrity.art",
            stubFinding(kind = "hook_framework_present", subject = "frida"),
        )
        assertNotEquals(a, b)
    }

    @Test
    fun `identityKey distinguishes by kind`() {
        val a = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "hook_framework_present", subject = "frida"),
        )
        val b = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "rwx_memory_mapping", subject = "frida"),
        )
        assertNotEquals(a, b)
    }

    @Test
    fun `identityKey distinguishes by subject`() {
        val a = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "dex_in_anonymous_mapping", subject = "io.ssemaj.sample"),
        )
        val b = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "dex_in_anonymous_mapping", subject = "io.ssemaj.other"),
        )
        assertNotEquals(a, b)
    }

    @Test
    fun `identityKey treats null subject and empty subject as identical`() {
        val a = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "k", subject = null),
        )
        val b = SessionFindingsAggregator.identityKey(
            "runtime.environment",
            stubFinding(kind = "k", subject = ""),
        )
        assertEquals(a, b)
    }

    // ---- single ingest --------------------------------------------------

    @Test
    fun `single report produces one TrackedFinding per finding all stillActive`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val report = stubReport(
            collectedAtEpochMs = 2000L,
            detectors = listOf(
                stubDetector("runtime.environment", listOf(
                    stubFinding(kind = "hook_framework_present", subject = "frida"),
                    stubFinding(kind = "rwx_memory_mapping", subject = "anon"),
                )),
            ),
        )

        val session = agg.ingest(report)

        assertEquals(2, session.findings.size)
        assertSame(report, session.latestReport)
        assertEquals(1, session.collectionsObserved)
        assertEquals(1000L, session.sessionStartedAtEpochMs)
        assertEquals(2000L, session.lastUpdatedAtEpochMs)
        for (entry in session.findings) {
            assertEquals(2000L, entry.firstSeenAtEpochMs)
            assertEquals(2000L, entry.lastSeenAtEpochMs)
            assertEquals(1, entry.observationCount)
            assertTrue("freshly observed finding must be stillActive", entry.stillActive)
        }
    }

    @Test
    fun `empty report produces empty session findings`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val report = stubReport(collectedAtEpochMs = 2000L, detectors = emptyList())

        val session = agg.ingest(report)

        assertTrue(session.findings.isEmpty())
        assertEquals(1, session.collectionsObserved)
    }

    // ---- repeated observation -----------------------------------------

    @Test
    fun `re-observing the same finding increments count and refreshes lastSeenAt`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val finding = stubFinding(kind = "hook_framework_present", subject = "frida")

        agg.ingest(stubReport(2000L, listOf(stubDetector("runtime.environment", listOf(finding)))))
        val second = agg.ingest(stubReport(3000L, listOf(stubDetector("runtime.environment", listOf(finding)))))

        assertEquals(1, second.findings.size)
        val entry = second.findings.single()
        assertEquals(2000L, entry.firstSeenAtEpochMs)
        assertEquals(3000L, entry.lastSeenAtEpochMs)
        assertEquals(2, entry.observationCount)
        assertTrue(entry.stillActive)
    }

    @Test
    fun `embedded Finding is refreshed to the most recent observation`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val first = stubFinding(kind = "k", subject = "s", message = "first message")
        val second = stubFinding(kind = "k", subject = "s", message = "updated message")

        agg.ingest(stubReport(2000L, listOf(stubDetector("d", listOf(first)))))
        val session = agg.ingest(stubReport(3000L, listOf(stubDetector("d", listOf(second)))))

        assertEquals("updated message", session.findings.single().finding.message)
    }

    // ---- disappear / reappear ------------------------------------------

    @Test
    fun `finding absent from latest report flips stillActive to false`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val finding = stubFinding(kind = "k", subject = "s")

        agg.ingest(stubReport(2000L, listOf(stubDetector("d", listOf(finding)))))
        val second = agg.ingest(stubReport(3000L, listOf(stubDetector("d", emptyList()))))

        assertEquals(1, second.findings.size)
        val entry = second.findings.single()
        assertFalse("disappeared finding must flip stillActive=false", entry.stillActive)
        // lastSeenAtEpochMs MUST stay at the timestamp of last
        // observation (2000), NOT update to the latest collect (3000).
        // The contract is: lastSeenAt = the wall-clock time we last
        // SAW it, not the wall-clock time we last LOOKED for it.
        assertEquals(2000L, entry.lastSeenAtEpochMs)
        assertEquals(1, entry.observationCount)
    }

    @Test
    fun `finding that re-appears flips back to stillActive=true and increments count`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val finding = stubFinding(kind = "k", subject = "s")

        agg.ingest(stubReport(2000L, listOf(stubDetector("d", listOf(finding)))))
        agg.ingest(stubReport(3000L, listOf(stubDetector("d", emptyList()))))
        val third = agg.ingest(stubReport(4000L, listOf(stubDetector("d", listOf(finding)))))

        val entry = third.findings.single()
        assertTrue(entry.stillActive)
        assertEquals(2000L, entry.firstSeenAtEpochMs)
        assertEquals(4000L, entry.lastSeenAtEpochMs)
        assertEquals(2, entry.observationCount)
    }

    @Test
    fun `disappeared finding stays in the list across many subsequent empty reports`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val finding = stubFinding(kind = "k", subject = "s")

        agg.ingest(stubReport(2000L, listOf(stubDetector("d", listOf(finding)))))
        var session = agg.ingest(stubReport(3000L, listOf(stubDetector("d", emptyList()))))
        assertEquals(1, session.findings.size)
        session = agg.ingest(stubReport(4000L, emptyList()))
        assertEquals(1, session.findings.size)
        session = agg.ingest(stubReport(5000L, emptyList()))
        assertEquals(1, session.findings.size)
        assertFalse(session.findings.single().stillActive)
        assertEquals(4, session.collectionsObserved)
    }

    // ---- ordering -------------------------------------------------------

    @Test
    fun `findings are returned in first-seen order`() {
        val agg = SessionFindingsAggregator(sessionStartedAtEpochMs = 1000L)
        val a = stubFinding(kind = "kA", subject = "x")
        val b = stubFinding(kind = "kB", subject = "x")
        val c = stubFinding(kind = "kC", subject = "x")

        agg.ingest(stubReport(2000L, listOf(stubDetector("d", listOf(a)))))
        agg.ingest(stubReport(3000L, listOf(stubDetector("d", listOf(a, b)))))
        val third = agg.ingest(stubReport(4000L, listOf(stubDetector("d", listOf(a, b, c)))))

        assertEquals(listOf("kA", "kB", "kC"), third.findings.map { it.finding.kind })
    }

    // ---- flow wrapper ---------------------------------------------------

    @Test
    fun `observeSessionFlow emits SessionFindings per upstream report`() = runTest {
        val r1 = stubReport(2000L, listOf(stubDetector("d", listOf(stubFinding("k1", "s")))))
        val r2 = stubReport(3000L, listOf(stubDetector("d", listOf(stubFinding("k1", "s"), stubFinding("k2", "s")))))
        val r3 = stubReport(4000L, listOf(stubDetector("d", listOf(stubFinding("k2", "s")))))

        val emitted = DeviceIntelligence.observeSessionFlow(flowOf(r1, r2, r3)).toList()

        assertEquals(3, emitted.size)
        // After r1: 1 finding (k1, active)
        assertEquals(1, emitted[0].findings.size)
        assertTrue(emitted[0].findings.single().stillActive)
        // After r2: 2 findings (k1 active, k2 active)
        assertEquals(2, emitted[1].findings.size)
        assertTrue(emitted[1].findings.all { it.stillActive })
        // After r3: 2 findings (k1 inactive, k2 active)
        assertEquals(2, emitted[2].findings.size)
        val k1Entry = emitted[2].findings.first { it.finding.kind == "k1" }
        val k2Entry = emitted[2].findings.first { it.finding.kind == "k2" }
        assertFalse(k1Entry.stillActive)
        assertTrue(k2Entry.stillActive)
    }

    @Test
    fun `each collector of observeSessionFlow gets independent session state`() = runTest {
        val r1 = stubReport(2000L, listOf(stubDetector("d", listOf(stubFinding("k", "s")))))
        val flow = DeviceIntelligence.observeSessionFlow(flowOf(r1))

        val first = flow.toList()
        val second = flow.toList()

        // Both collectors see observationCount=1 (not 2). If they
        // shared aggregator state, the second collect would emit
        // observationCount=2 because the same r1 was ingested twice.
        assertEquals(1, first.single().findings.single().observationCount)
        assertEquals(1, second.single().findings.single().observationCount)
    }
}
