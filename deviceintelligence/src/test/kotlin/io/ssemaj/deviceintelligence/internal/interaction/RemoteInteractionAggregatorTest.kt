package io.ssemaj.deviceintelligence.internal.interaction

import io.ssemaj.deviceintelligence.InteractionEvent
import io.ssemaj.deviceintelligence.InteractionEventKind
import io.ssemaj.deviceintelligence.InteractionSeverity
import io.ssemaj.deviceintelligence.InteractionSource
import io.ssemaj.deviceintelligence.MatchStrategy
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Aggregator contract pinned: emit ordering, rolling counts,
 * severity bump, snapshot folding, and SharedFlow replay semantics.
 *
 * No detectors emit in Phase 1; this test feeds events directly
 * via the internal `emit()` entry to validate the aggregator's
 * behavior independently.
 */
class RemoteInteractionAggregatorTest {

    @Test
    fun `freshly constructed aggregator has empty snapshot`() {
        val agg = RemoteInteractionAggregator.forTesting()
        val snap = agg.snapshot()
        assertEquals(emptyMap<InteractionEventKind, Int>(), snap.eventCounts)
        assertEquals(InteractionSeverity.INFO, snap.highestSeverityObserved)
    }

    @Test
    fun `emit increments per-kind count`() {
        val agg = RemoteInteractionAggregator.forTesting()
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        agg.emit(sampleEvent(InteractionSeverity.HIGH))
        val snap = agg.snapshot()
        assertEquals(3, snap.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }

    @Test
    fun `highest severity observed monotonically increases`() {
        val agg = RemoteInteractionAggregator.forTesting()
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        assertEquals(InteractionSeverity.INFO, agg.snapshot().highestSeverityObserved)
        agg.emit(sampleEvent(InteractionSeverity.MEDIUM))
        assertEquals(InteractionSeverity.MEDIUM, agg.snapshot().highestSeverityObserved)
        agg.emit(sampleEvent(InteractionSeverity.HIGH))
        assertEquals(InteractionSeverity.HIGH, agg.snapshot().highestSeverityObserved)
        // INFO after HIGH must NOT drop the high-water mark
        agg.emit(sampleEvent(InteractionSeverity.INFO))
        assertEquals(InteractionSeverity.HIGH, agg.snapshot().highestSeverityObserved)
    }

    @Test
    fun `emitted events flow through SharedFlow in order`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        val first = sampleEvent(InteractionSeverity.INFO, timestampMs = 100L)
        val second = sampleEvent(InteractionSeverity.HIGH, timestampMs = 200L)
        agg.emit(first)
        agg.emit(second)
        // Replay buffer of 16 means late collectors see the prior events.
        val collected = agg.events.take(2).toList()
        assertEquals(listOf(first, second), collected)
    }

    @Test
    fun `events SharedFlow replays last events to new collectors`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        agg.emit(sampleEvent(InteractionSeverity.HIGH))
        // Subscribing AFTER emit: replay should deliver the missed event.
        val ev = agg.events.first()
        assertNotNull(ev)
        assertEquals(InteractionSeverity.HIGH, ev.severity)
    }

    @Test
    fun `concurrent emits from N threads produce deterministic count rollup`() {
        val agg = RemoteInteractionAggregator.forTesting()
        val threadCount = 16
        val perThread = 250
        val expectedTotal = threadCount * perThread

        val threads = (0 until threadCount).map {
            Thread {
                repeat(perThread) {
                    agg.emit(sampleEvent(InteractionSeverity.MEDIUM))
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val snap = agg.snapshot()
        // Every emit increments the count; aggregator must lose nothing.
        assertEquals(expectedTotal, snap.eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
        // Severity reached at least MEDIUM.
        assertEquals(InteractionSeverity.MEDIUM, snap.highestSeverityObserved)
    }

    @Test
    fun `DROP_OLDEST means flood does not throw and counts still reflect every emit`() {
        // No collector subscribed — buffer fills, then drops oldest.
        // The accounting (counts + severity) must still be exact because
        // emit() updates counts BEFORE attempting tryEmit.
        val agg = RemoteInteractionAggregator.forTesting(replayCount = 2, bufferCapacity = 4)
        val emitCount = 10_000
        repeat(emitCount) {
            agg.emit(sampleEvent(InteractionSeverity.INFO))
        }
        assertEquals(emitCount, agg.snapshot().eventCounts[InteractionEventKind.A11Y_SERVICE_ENABLED])
    }

    private fun sampleEvent(
        severity: InteractionSeverity,
        timestampMs: Long = 1L,
    ): InteractionEvent = InteractionEvent.A11yServiceEnabled(
        packageName = "com.example",
        serviceName = "com.example/.S",
        capabilities = emptySet(),
        installerPackage = null,
        firstInstallMs = 0L,
        severity = severity,
        timestampMs = timestampMs,
        source = InteractionSource.SNAPSHOT,
    )
}
