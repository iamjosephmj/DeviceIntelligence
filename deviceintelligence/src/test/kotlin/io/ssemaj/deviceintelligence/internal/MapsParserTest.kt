package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the [MapsParser]. Feeds canned `/proc/self/maps`
 * snippets — including ones taken straight from real Pixel devices —
 * and asserts on what the scanner extracts.
 *
 * No Android infrastructure: the parser is intentionally a
 * string-in / data-class-out pure function so this whole suite is
 * a single test class with hand-written fixtures.
 */
class MapsParserTest {

    @Test
    fun `clean process map yields no findings`() {
        val maps = """
            720000000-720001000 r--p 00000000 fd:00 12345 /system/lib64/libc.so
            720001000-720010000 r-xp 00001000 fd:00 12345 /system/lib64/libc.so
            720010000-720011000 rw-p 00010000 fd:00 12345 /system/lib64/libc.so
            720011000-720012000 ---p 00000000 00:00 0
            720012000-720013000 rw-p 00000000 00:00 0  [anon:libc_globals]
            720013000-720014000 r--p 00000000 fd:00 67890 /system/framework/core-libart.jar
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.hookFrameworks)
        assertEquals(emptyList<String>(), result.rwxRegions)
    }

    @Test
    fun `frida-agent in pathname is detected as frida`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/local/tmp/frida-agent-arm64.so
            720001000-720002000 r--p 00001000 fd:00 12345 /data/local/tmp/frida-agent-arm64.so
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(listOf("frida"), result.hookFrameworks)
    }

    @Test
    fun `xposed bridge jar in pathname is detected as xposed`() {
        val maps = """
            720000000-720001000 r--p 00000000 fd:00 12345 /system/framework/XposedBridge.jar
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(listOf("xposed"), result.hookFrameworks)
    }

    @Test
    fun `lspd marker is detected as lsposed`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /apex/com.android.runtime/lspd_helper.so
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(listOf("lsposed"), result.hookFrameworks)
    }

    @Test
    fun `multiple frida signatures still produce one finding per framework`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/local/tmp/frida-agent-arm64.so
            720001000-720002000 r-xp 00000000 fd:00 12345 /data/local/tmp/frida-gadget-arm64.so
            720002000-720003000 r-xp 00000000 fd:00 12345 /data/local/tmp/something-with-gum-js-loop
        """.trimIndent()

        val result = MapsParser.parse(maps)

        // Three lines hit frida sigs — only one entry, deduped on
        // canonical name.
        assertEquals(listOf("frida"), result.hookFrameworks)
    }

    @Test
    fun `multiple distinct frameworks are reported separately`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/local/tmp/frida-agent-arm64.so
            720001000-720002000 r--p 00000000 fd:00 12345 /system/framework/XposedBridge.jar
            720002000-720003000 r-xp 00000000 fd:00 12345 /system/lib64/libriru-sample.so
        """.trimIndent()

        val result = MapsParser.parse(maps)

        // Order matches first-seen-line via LinkedHashSet.
        assertEquals(listOf("frida", "xposed", "riru"), result.hookFrameworks)
    }

    @Test
    fun `rwxp anonymous mapping is captured`() {
        val maps = """
            720000000-720001000 r--p 00000000 fd:00 12345 /system/lib64/libc.so
            720001000-720002000 rwxp 00000000 00:00 0
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(listOf("720001000-720002000 [anon]"), result.rwxRegions)
    }

    @Test
    fun `rwxp named mapping captures pathname in descriptor`() {
        val maps = """
            720001000-720002000 rwxp 00000000 fd:00 12345 /data/local/tmp/jit-region.bin
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(
            listOf("720001000-720002000 /data/local/tmp/jit-region.bin"),
            result.rwxRegions,
        )
    }

    @Test
    fun `rwxs shared mapping is also captured`() {
        val maps = """
            720001000-720002000 rwxs 00000000 fd:00 12345 /dev/shm/foo
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(
            listOf("720001000-720002000 /dev/shm/foo"),
            result.rwxRegions,
        )
    }

    @Test
    fun `rwx region list is capped with overflow descriptor`() {
        // Generate 12 RWX lines to overflow the cap of 8.
        val builder = StringBuilder()
        for (i in 0 until 12) {
            builder.append(
                String.format(
                    "%016x-%016x rwxp 00000000 00:00 0\n",
                    0x720000000L + i * 0x1000,
                    0x720000000L + (i + 1) * 0x1000,
                )
            )
        }

        val result = MapsParser.parse(builder.toString())

        // 8 region descriptors + 1 overflow line = 9.
        assertEquals(9, result.rwxRegions.size)
        assertTrue(result.rwxRegions.last().startsWith("... +"))
        assertTrue(result.rwxRegions.last().endsWith(" more"))
    }

    @Test
    fun `non-executable mappings are not flagged as rwx`() {
        val maps = """
            720000000-720001000 rw-p 00000000 fd:00 12345 /data/heap
            720001000-720002000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so
            720002000-720003000 r--p 00000000 fd:00 12345 /system/lib64/libc.so
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.rwxRegions)
    }

    @Test
    fun `empty input yields empty result`() {
        val result = MapsParser.parse("")

        assertEquals(emptyList<String>(), result.hookFrameworks)
        assertEquals(emptyList<String>(), result.rwxRegions)
    }

    // ---- scanDalvikAnonRegions ------------------------------------------

    @Test
    fun `scanDalvikAnonRegions returns empty when no dalvik-named regions are present`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so
            720001000-720002000 rw-p 00000000 00:00 0  [anon:libc_globals]
            720002000-720003000 rw-p 00000000 00:00 0  [anon:scudo:primary]
        """.trimIndent()

        val result = MapsParser.scanDalvikAnonRegions(maps)

        assertEquals(emptyList<MapsParser.DalvikAnonRegion>(), result)
    }

    @Test
    fun `scanDalvikAnonRegions captures InMemoryDexClassLoader-style label`() {
        val maps = """
            7090000000-7090001000 rw-p 00000000 00:00 0  [anon:dalvik-classes.dex extracted in memory from <buffer>]
        """.trimIndent()

        val result = MapsParser.scanDalvikAnonRegions(maps)

        assertEquals(1, result.size)
        val region = result[0]
        assertEquals("7090000000-7090001000", region.addressRange)
        assertEquals("rw-p", region.perms)
        assertEquals(
            "anon:dalvik-classes.dex extracted in memory from <buffer>",
            region.label,
        )
    }

    @Test
    fun `scanDalvikAnonRegions captures path-backed extraction labels`() {
        val maps = """
            7090000000-7090001000 rw-p 00000000 00:00 0  [anon:dalvik-classes.dex extracted in memory from /data/local/tmp/payload.dex]
            7090001000-7090002000 rw-p 00000000 00:00 0  [anon:dalvik-classes.dex extracted in memory from /data/app/com.example.app-AbC/base.apk]
        """.trimIndent()

        val result = MapsParser.scanDalvikAnonRegions(maps)

        assertEquals(2, result.size)
        assertTrue(result[0].label.endsWith("/data/local/tmp/payload.dex"))
        assertTrue(result[1].label.contains("com.example.app"))
    }

    @Test
    fun `scanDalvikAnonRegions captures jit-cache and other dalvik internals`() {
        // These are NOT DEX content; the parser should still surface
        // them — the detector classifies the kind, not the parser.
        val maps = """
            7090000000-7090001000 rwxp 00000000 00:00 0  [anon:dalvik-jit-code-cache]
            7090001000-7090002000 rw-p 00000000 00:00 0  [anon:dalvik-zygote-claimed]
            7090002000-7090003000 rw-p 00000000 00:00 0  [anon:dalvik-LinearAlloc]
        """.trimIndent()

        val result = MapsParser.scanDalvikAnonRegions(maps)

        assertEquals(3, result.size)
        assertEquals("anon:dalvik-jit-code-cache", result[0].label)
        assertEquals("anon:dalvik-zygote-claimed", result[1].label)
        assertEquals("anon:dalvik-LinearAlloc", result[2].label)
    }

    @Test
    fun `scanDalvikAnonRegions ignores non-dalvik named anon regions`() {
        val maps = """
            7090000000-7090001000 rw-p 00000000 00:00 0  [anon:libc_malloc]
            7090001000-7090002000 rw-p 00000000 00:00 0  [anon:scudo:primary]
            7090002000-7090003000 rw-p 00000000 00:00 0  [anon:dalvik-classes.dex extracted in memory from <buffer>]
        """.trimIndent()

        val result = MapsParser.scanDalvikAnonRegions(maps)

        assertEquals(1, result.size)
        assertTrue(result[0].label.startsWith("anon:dalvik-"))
    }

    @Test
    fun `scanDalvikAnonRegions empty input yields empty list`() {
        val result = MapsParser.scanDalvikAnonRegions("")
        assertEquals(emptyList<MapsParser.DalvikAnonRegion>(), result)
    }

    @Test
    fun `anonymous mapping never matches a hook signature`() {
        // Anonymous maps have no pathname; even if the signature
        // string appears in the address column (it can't, but
        // verify we don't get confused) we should not match.
        val maps = """
            frida0000-frida0001 r-xp 00000000 00:00 0
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.hookFrameworks)
    }
}
