package io.ssemaj.deviceintelligence.internal.interaction

import io.ssemaj.deviceintelligence.InteractionEvent
import io.ssemaj.deviceintelligence.InteractionEventKind
import io.ssemaj.deviceintelligence.InteractionSeverity
import io.ssemaj.deviceintelligence.RemoteInteractionFindings
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Process-singleton sink for [InteractionEvent]s emitted by all
 * three data paths (snapshot detectors, system listeners,
 * bytecode-injected hooks). Constructed at boot by
 * [io.ssemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider]
 * and exposed on [io.ssemaj.deviceintelligence.DeviceIntelligence.interactionEvents].
 *
 * Thread-safety: every member is safe for concurrent access from
 * any thread. The hot path ([emit]) is allocation-free for the
 * accounting work (`AtomicInteger.incrementAndGet`,
 * `ConcurrentHashMap.computeIfAbsent`) and uses [MutableSharedFlow.tryEmit]
 * with [BufferOverflow.DROP_OLDEST] so emitters never suspend.
 *
 * Buffer sizing rationale:
 *  - replay = 16: a screen that subscribes mid-session sees the
 *    last ~16 events (typically enough to render a meaningful
 *    "what's happened in this session" timeline).
 *  - extraBufferCapacity = 64: tolerates short consumer stalls
 *    without dropping; bytecode-injected hot path can flush
 *    bursts (e.g. rapid touch sequence).
 *  - DROP_OLDEST: a wedged consumer never back-pressures the UI
 *    thread; the SDK silently loses the oldest unread events.
 */
internal class RemoteInteractionAggregator private constructor(
    replayCount: Int,
    bufferCapacity: Int,
) {
    private val _events = MutableSharedFlow<InteractionEvent>(
        replay = replayCount,
        extraBufferCapacity = bufferCapacity,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    /**
     * Hot stream of every event the aggregator has accepted.
     * Backed by a [MutableSharedFlow] with [BufferOverflow.DROP_OLDEST]
     * so subscribers cannot back-pressure emitters.
     */
    val events: SharedFlow<InteractionEvent> = _events.asSharedFlow()

    private val counts = ConcurrentHashMap<InteractionEventKind, AtomicInteger>()
    private val highestSeverity = AtomicReference(InteractionSeverity.INFO)

    /**
     * Records an event into the rolling state and emits it on the
     * shared flow. Non-suspending; safe to call from the UI thread.
     */
    fun emit(event: InteractionEvent) {
        counts.computeIfAbsent(event.kind) { AtomicInteger(0) }.incrementAndGet()
        bumpSeverity(event.severity)
        _events.tryEmit(event)
    }

    /**
     * Folds the rolling state into the public snapshot embedded in
     * [io.ssemaj.deviceintelligence.SessionFindings.remoteInteraction].
     * Phase 1: only `eventCounts` and `highestSeverityObserved` are
     * populated; remaining fields stay at [RemoteInteractionFindings.EMPTY]
     * defaults until detectors land in subsequent phases.
     */
    fun snapshot(): RemoteInteractionFindings {
        val countSnap: Map<InteractionEventKind, Int> = counts
            .mapValues { (_, v) -> v.get() }
            .filterValues { it > 0 }
        return RemoteInteractionFindings.EMPTY.copy(
            eventCounts = countSnap,
            highestSeverityObserved = highestSeverity.get(),
        )
    }

    private fun bumpSeverity(observed: InteractionSeverity) {
        while (true) {
            val current = highestSeverity.get()
            if (observed.ordinal <= current.ordinal) return
            if (highestSeverity.compareAndSet(current, observed)) return
        }
    }

    companion object {
        const val DEFAULT_REPLAY: Int = 16
        const val DEFAULT_BUFFER: Int = 64

        /** Production constructor — used by `DeviceIntelligenceInitProvider`. */
        fun newProductionInstance(): RemoteInteractionAggregator =
            RemoteInteractionAggregator(DEFAULT_REPLAY, DEFAULT_BUFFER)

        /** Test constructor — explicit smaller buffers for deterministic flood tests. */
        internal fun forTesting(
            replayCount: Int = DEFAULT_REPLAY,
            bufferCapacity: Int = DEFAULT_BUFFER,
        ): RemoteInteractionAggregator =
            RemoteInteractionAggregator(replayCount, bufferCapacity)
    }
}
