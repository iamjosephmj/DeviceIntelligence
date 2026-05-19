package io.ssemaj.deviceintelligence

import io.ssemaj.deviceintelligence.internal.interaction.RemoteInteractionAggregator
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Pins the public-API contract: `DeviceIntelligence.interactionEvents`
 * is a non-null `SharedFlow<InteractionEvent>` backed by the
 * process-singleton aggregator that `DeviceIntelligenceInitProvider`
 * constructs at boot.
 *
 * In a pure-JVM test the InitProvider's `onCreate` never runs, so
 * this test goes through the internal install hook to seed an
 * aggregator instance. Production seeding happens in
 * `DeviceIntelligenceInitProvider.onCreate`.
 */
class InteractionEventsPropertyTest {

    @Test
    fun `interactionEvents property is non-null after aggregator installed`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        DeviceIntelligence.installRemoteInteractionAggregator(agg)
        assertNotNull(DeviceIntelligence.interactionEvents)
    }

    @Test
    fun `events emitted on aggregator surface on DeviceIntelligence interactionEvents`() = runTest {
        val agg = RemoteInteractionAggregator.forTesting()
        DeviceIntelligence.installRemoteInteractionAggregator(agg)

        val event = InteractionEvent.A11yServiceEnabled(
            packageName = "com.example",
            serviceName = "com.example/.S",
            capabilities = emptySet(),
            installerPackage = null,
            firstInstallMs = 0L,
            severity = InteractionSeverity.HIGH,
            timestampMs = 99L,
            source = InteractionSource.SNAPSHOT,
        )
        agg.emit(event)

        // Replay buffer means first() returns the just-emitted event.
        val received = DeviceIntelligence.interactionEvents.first()
        assertEquals(event, received)
    }
}
