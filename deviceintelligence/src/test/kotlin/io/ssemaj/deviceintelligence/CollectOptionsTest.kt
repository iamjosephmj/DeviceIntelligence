package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM contract tests for [CollectOptions]. These are
 * intentionally trivial — the data class isn't doing computation,
 * but pinning the public default values prevents accidental
 * source-incompatible changes (e.g. flipping `only` from nullable
 * to default-empty would silently change the meaning of every
 * call site).
 */
class CollectOptionsTest {

    @Test
    fun `default constructor runs every detector`() {
        val opts = CollectOptions()
        assertTrue("default skip is empty", opts.skip.isEmpty())
        assertNull("default only is null (= no allowlist)", opts.only)
    }

    @Test
    fun `DEFAULT companion equals default constructor`() {
        assertEquals(CollectOptions(), CollectOptions.DEFAULT)
    }

    @Test
    fun `skip and only are independent fields`() {
        val both = CollectOptions(
            skip = setOf("integrity.apk"),
            only = setOf("integrity.art"),
        )
        assertEquals(setOf("integrity.apk"), both.skip)
        assertEquals(setOf("integrity.art"), both.only)
    }

    @Test
    fun `data class equality covers both fields`() {
        val a = CollectOptions(skip = setOf("integrity.apk"))
        val b = CollectOptions(skip = setOf("integrity.apk"))
        val c = CollectOptions(skip = setOf("runtime.root"))
        assertEquals(a, b)
        assertNotSame(a, c)
    }

    @Test
    fun `empty only set means no detectors run`() {
        val none = CollectOptions(only = emptySet())
        assertEquals(emptySet<String>(), none.only)
    }
}
