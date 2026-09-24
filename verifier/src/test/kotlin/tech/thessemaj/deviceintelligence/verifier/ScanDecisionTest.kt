package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/**
 * The default-policy mapping on [ScanResult.decision] — the readable on-ramp.
 * These tests pin the CONTRACT backends code against: forgery → REJECT,
 * bad device or blocking signal → COMPROMISED, otherwise TRUSTWORTHY — and
 * that the mapping reads only the graded axes, never anything else.
 */
class ScanDecisionTest {

    private fun signal(id: String, blocking: Boolean) = ResolvedSignal(
        id = id, detector = "t", kind = "t", title = "", severity = "HIGH",
        detail = "", blocking = blocking,
    )

    private fun result(
        ok: Boolean,
        deviceIntegrityOk: Boolean = true,
        signals: List<ResolvedSignal> = emptyList(),
    ) = ScanResult(
        ok = ok, bootstrap = false, deviceIntegrityOk = deviceIntegrityOk,
        session = null, checks = emptyList(), signals = signals,
        reason = if (ok) null else "forgery",
    )

    @Test fun a_proven_forgery_is_rejected_even_if_everything_else_looks_clean() {
        assertEquals(Decision.REJECT, result(ok = false, deviceIntegrityOk = true).decision)
    }

    @Test fun an_untrustworthy_device_is_compromised_not_rejected() {
        // Honest report of a bad device: authentic token, so REJECT would be wrong.
        assertEquals(
            Decision.COMPROMISED,
            result(ok = true, deviceIntegrityOk = false).decision,
        )
    }

    @Test fun a_blocking_signal_is_compromised() {
        assertEquals(
            Decision.COMPROMISED,
            result(ok = true, signals = listOf(signal("INTEL_0008", blocking = true))).decision,
        )
    }

    @Test fun a_non_blocking_signal_stays_trustworthy() {
        assertEquals(
            Decision.TRUSTWORTHY,
            result(ok = true, signals = listOf(signal("INTEL_0044", blocking = false))).decision,
        )
    }

    @Test fun clean_scan_is_trustworthy() {
        assertEquals(Decision.TRUSTWORTHY, result(ok = true).decision)
    }

    @Test fun blockingSignals_carries_only_the_blocking_findings() {
        val r = result(
            ok = true,
            signals = listOf(
                signal("INTEL_0044", blocking = false),
                signal("INTEL_0008", blocking = true),
                signal("INTEL_0035", blocking = true),
            ),
        )
        assertEquals(listOf("INTEL_0008", "INTEL_0035"), r.blockingSignals.map { it.id })
    }

    @Test fun forgery_wins_over_everything() {
        // Both axes bad + blocking signal: still REJECT — contents are not trustworthy.
        val r = result(ok = false, deviceIntegrityOk = false, signals = listOf(signal("INTEL_0008", true)))
        assertEquals(Decision.REJECT, r.decision)
    }
}
