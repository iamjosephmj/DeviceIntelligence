package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyTest {
    private val policy = Policy()

    @Test fun `critical severity blocks`() = assertTrue(policy.isBlocking("INTEL_0001", "CRITICAL"))

    @Test fun `non-critical severity does not block by default`() {
        assertFalse(policy.isBlocking("INTEL_0019", "HIGH"))
        assertFalse(policy.isBlocking("INTEL_0050", "MEDIUM"))
    }

    @Test fun `allow list overrides severity`() {
        val p = Policy(allow = setOf("INTEL_0052"))
        assertFalse(p.isBlocking("INTEL_0052", "CRITICAL"))
    }

    @Test fun `block list overrides severity`() {
        val p = Policy(block = setOf("INTEL_0050"))
        assertTrue(p.isBlocking("INTEL_0050", "MEDIUM"))
    }

    @Test fun `allow takes precedence over block and severity`() {
        val p = Policy(allow = setOf("INTEL_0001"), block = setOf("INTEL_0001"))
        assertFalse(p.isBlocking("INTEL_0001", "CRITICAL"))
    }

    @Test fun `severity comparison is case-insensitive`() = assertTrue(policy.isBlocking(null, "critical"))

    @Test fun `null severity does not block by default`() = assertFalse(policy.isBlocking(null, null))

    @Test fun `confirmed rwx hook pool always blocks`() {
        val p = Policy(observeUnconfirmedRwx = true)
        assertTrue(p.isBlocking("INTEL_0052", "CRITICAL", kind = "rwx_memory_mapping", hookStubRegions = 3))
    }

    @Test fun `bare rwx downgrades only when opted in`() {
        val id = "INTEL_0052"
        assertTrue(policy.isBlocking(id, "CRITICAL", kind = "rwx_memory_mapping", hookStubRegions = 0))
        val relaxed = Policy(observeUnconfirmedRwx = true)
        assertFalse(relaxed.isBlocking(id, "CRITICAL", kind = "rwx_memory_mapping", hookStubRegions = 0))
    }
}
