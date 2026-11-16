package tech.thessemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SignerBaselineGateTest {
    @Test
    fun `pin configured allows`() {
        assertEquals(SignerBaselineGate.Allow,
            SignerBaselineGate.decide("a9153578", null))
    }

    @Test
    fun `explicit skip allows with reason`() {
        val d = SignerBaselineGate.decide(null, "true")
        assertTrue(d is SignerBaselineGate.AllowDeferred)
        assertTrue((d as SignerBaselineGate.AllowDeferred).reason.contains("skip"))
    }

    @Test
    fun `neither pin nor skip fails release`() {
        val d = SignerBaselineGate.decide(null, null)
        assertTrue(d is SignerBaselineGate.Fail)
        assertTrue((d as SignerBaselineGate.Fail).reason.contains("deviceintelligence.expectedSigner"))
    }

    @Test
    fun `skip set to anything counts as explicit`() {
        assertTrue(SignerBaselineGate.decide(null, "false") is SignerBaselineGate.AllowDeferred)
    }
}
