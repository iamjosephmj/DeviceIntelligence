package tech.thessemaj.deviceintelligence.sample.signal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalCatalogueTest {
    @Test fun `every entry resolves from its own code`() {
        for (entry in SignalCatalogue.entries) assertNotNull(SignalCatalogue.of(entry.name))
    }

    @Test fun `unknown codes return null`() = assertNull(SignalCatalogue.of("INTEL_9999"))

    @Test fun `the catalogue carries all sixty four codes, three of them retired`() {
        assertEquals(64, SignalCatalogue.entries.size)
        assertEquals(3, SignalCatalogue.entries.count { it.retired })
    }
}
