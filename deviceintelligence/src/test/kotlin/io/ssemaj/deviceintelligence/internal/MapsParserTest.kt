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

    // ---- newer hook framework signatures (CTF Flag 2) ------------------

    @Test
    fun `dobby library name is detected`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/local/tmp/libdobby.so
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("dobby"), result.hookFrameworks)
    }

    @Test
    fun `dobby_bridge symbol-derived map name is detected`() {
        // Some Dobby builds expose the bridge as a separate small
        // mapping name. Either signature should trip.
        val maps = """
            720000000-720001000 r-xp 00000000 00:00 0  [anon:dobby_bridge]
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("dobby"), result.hookFrameworks)
    }

    @Test
    fun `whale library is detected`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/local/tmp/libwhale.so
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("whale"), result.hookFrameworks)
    }

    @Test
    fun `yahfa library is detected`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /apex/com.android.runtime/libyahfa.so
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("yahfa"), result.hookFrameworks)
    }

    @Test
    fun `fasthook library is detected`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/local/tmp/libfasthook.so
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("fasthook"), result.hookFrameworks)
    }

    @Test
    fun `il2cppdumper library is detected`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/adb/modules/zygisk-il2cppdumper/lib/arm64-v8a/libil2cppdumper.so
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("il2cpp_dumper"), result.hookFrameworks)
    }

    @Test
    fun `zygisk-il2cpp module path is detected even without library suffix`() {
        // Some Zygisk packagings expose the module via the directory
        // name in a maps line that doesn't include the .so basename.
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/adb/modules/zygisk-il2cppdumper/companion
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(listOf("il2cpp_dumper"), result.hookFrameworks)
    }

    @Test
    fun `intentionally-skipped frameworks (shadowhook, pine, sandhook) do not trip`() {
        // These are deliberately NOT in the signature list because
        // legitimate apps embed them. Flagging them on name alone
        // would FP on every Bytedance app (ShadowHook), every
        // ART-instrumentation framework (Pine), every EdXposed-
        // backend-using consumer (SandHook). Until we have the
        // embedded-vs-injected distinction, name-only detection
        // for these is harmful.
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /data/app/com.example.app-AbC/lib/arm64-v8a/libshadowhook.so
            720001000-720002000 r-xp 00000000 fd:00 12345 /data/app/com.example.app-AbC/lib/arm64-v8a/libpine.so
            720002000-720003000 r-xp 00000000 fd:00 12345 /data/app/com.example.app-AbC/lib/arm64-v8a/libsandhook.so
        """.trimIndent()
        val result = MapsParser.parse(maps)
        assertEquals(emptyList<String>(), result.hookFrameworks)
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

    // ---- Frida 16+ memfd-backed Gum JIT signature ------------------------

    @Test
    fun `legitimate ART memfd jit-cache with r-xp perms is NOT flagged as frida memfd`() {
        // ART (Samsung/Android 16) legitimately maps /memfd:jit-cache
        // with r-xp / r--p / rw-p perms. None of them are rwxp, so the
        // detector must not flag any of these lines.
        val maps = """
            720000000-721000000 r-xp 00000000 00:0c 12345 /memfd:jit-cache (deleted)
            721000000-722000000 r--p 00000000 00:0c 12345 /memfd:jit-cache (deleted)
            722000000-723000000 rw-p 00000000 00:0c 12345 /memfd:jit-cache (deleted)
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.fridaMemfdJitRegions)
        // And no spurious RWX firing either.
        assertEquals(emptyList<String>(), result.rwxRegions)
    }

    @Test
    fun `frida memfd jit-cache with rwxp and large size IS flagged`() {
        // Frida 16+ Gum JIT: rwxp + /memfd:jit-cache + region size > 8 MB.
        // 0x720000000 → 0x721000000 = 0x01000000 = 16 MB, well above
        // the 8 MB threshold.
        val maps = """
            720000000-721000000 rwxp 00000000 00:0c 12345 /memfd:jit-cache (deleted)
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(
            listOf("720000000-721000000 /memfd:jit-cache (deleted)"),
            result.fridaMemfdJitRegions,
        )
        // The region also still appears in the generic rwxRegions
        // list — the more specific signal does NOT remove it.
        assertEquals(
            listOf("720000000-721000000 /memfd:jit-cache (deleted)"),
            result.rwxRegions,
        )
    }

    @Test
    fun `frida memfd jit-cache below 8MB threshold is NOT flagged as memfd jit`() {
        // 0x720000000 → 0x720100000 = 0x100000 = 1 MB, below the 8 MB
        // belt-and-suspenders threshold. Still appears in the generic
        // RWX list (rwxp is suspicious regardless of size), but not
        // in the more specific Frida-memfd-JIT attribution list.
        val maps = """
            720000000-720100000 rwxp 00000000 00:0c 12345 /memfd:jit-cache (deleted)
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.fridaMemfdJitRegions)
        assertEquals(1, result.rwxRegions.size)
    }

    @Test
    fun `non-memfd rwxp regions don't appear in the memfd jit list`() {
        val maps = """
            720000000-721000000 rwxp 00000000 00:00 0
            721000000-722000000 rwxp 00000000 fd:00 7777  /data/local/tmp/jit-region.bin
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.fridaMemfdJitRegions)
        // But both rwxp lines still hit the generic rwxRegions list.
        assertEquals(2, result.rwxRegions.size)
    }

    @Test
    fun `frida memfd jit detection handles malformed address ranges gracefully`() {
        // Defensive: a garbage address column should not crash the
        // parser, just skip the memfd-JIT classification for that
        // line. We deliberately include a well-formed RWX line after
        // the bad one to verify the parser keeps making progress.
        val maps = """
            nothex-still-nothex rwxp 00000000 00:0c 12345 /memfd:jit-cache (deleted)
            720000000-721000000 rwxp 00000000 00:0c 12345 /memfd:jit-cache (deleted)
        """.trimIndent()

        val result = MapsParser.parse(maps)

        // The malformed line should NOT appear in the memfd JIT list
        // (size can't be parsed) but should still appear in the
        // generic rwxRegions list since perms are explicit.
        assertEquals(1, result.fridaMemfdJitRegions.size)
        assertTrue(result.fridaMemfdJitRegions[0].startsWith("720000000-"))
    }

    @Test
    fun `clean map has empty memfd jit list`() {
        val maps = """
            720000000-720001000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so
        """.trimIndent()

        val result = MapsParser.parse(maps)

        assertEquals(emptyList<String>(), result.fridaMemfdJitRegions)
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
