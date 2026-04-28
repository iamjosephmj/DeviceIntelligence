package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pure-JVM tests for the testable surface of
 * [RuntimeEnvironmentDetector]. The bulk of the detector's logic
 * lives in [MapsParser] (covered by [MapsParserTest]); this class
 * exists to pin the wire-contract values backends rely on.
 */
class RuntimeEnvironmentDetectorTest {

    @Test
    fun `detector id matches the F16 contract`() {
        assertEquals("F16.runtime_environment", RuntimeEnvironmentDetector.id)
    }
}
