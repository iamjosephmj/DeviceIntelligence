package io.ssemaj.deviceintelligence.internal

import android.content.pm.ApplicationInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for [DexInjection]'s testable seams.
 *
 * `DexInjection` is an internal helper of
 * [RuntimeEnvironmentDetector]; its findings ride on the
 * `runtime.environment` wire contract (NOT a detector ID of its
 * own). Full integration path needs a live `Context` and
 * `BaseDexClassLoader` chain (verified on-device via the Flag 1
 * red-team harnesses). What we can pin in pure JVM:
 *  - `pathIsAllowed` — the path-allowlist contract for channel (a).
 *  - `classifyDalvikRegion` — the named-anon classification for
 *    channel (b).
 *  - The stable finding-kind constants don't drift accidentally —
 *    they're the wire-contract surface backends key on.
 *
 * `ApplicationInfo` is a public POJO whose fields can be set
 * directly even against the android.jar stub used in unit tests
 * (no method calls involved), so no Robolectric needed.
 */
class DexInjectionTest {

    private fun appInfoFor(
        packageName: String = "com.example.app",
        sourceDir: String = "/data/app/com.example.app-AbCdEf==/base.apk",
        splitSourceDirs: Array<String>? = null,
    ): ApplicationInfo {
        val ai = ApplicationInfo()
        ai.packageName = packageName
        ai.sourceDir = sourceDir
        ai.publicSourceDir = sourceDir
        ai.splitSourceDirs = splitSourceDirs
        return ai
    }

    // ---- finding kinds (stable wire contract) --------------------------

    @Test
    fun `finding kinds are stable wire identifiers`() {
        assertEquals("dex_classloader_added", DexInjection.KIND_CLASSLOADER_ADDED)
        assertEquals("dex_path_outside_apk", DexInjection.KIND_PATH_OUTSIDE_APK)
        assertEquals("dex_in_memory_loader_injected", DexInjection.KIND_IN_MEMORY_LOADER)
        assertEquals("dex_in_anonymous_mapping", DexInjection.KIND_ANON_MAPPING)
        assertEquals(
            "unattributable_dex_at_baseline",
            DexInjection.KIND_UNATTRIBUTABLE_AT_BASELINE,
        )
    }

    // ---- pathIsAllowed --------------------------------------------------

    @Test
    fun `app's own base apk is allowed`() {
        val ai = appInfoFor()
        assertTrue(DexInjection.pathIsAllowed(ai.sourceDir!!, ai))
    }

    @Test
    fun `app's split apk is allowed via splitSourceDirs`() {
        val splitPath = "/data/app/com.example.app-AbCdEf==/split_dynamic.apk"
        val ai = appInfoFor(splitSourceDirs = arrayOf(splitPath))
        assertTrue(DexInjection.pathIsAllowed(splitPath, ai))
    }

    @Test
    fun `system framework jars are allowed`() {
        val ai = appInfoFor()
        assertTrue(DexInjection.pathIsAllowed("/system/framework/core-libart.jar", ai))
        assertTrue(DexInjection.pathIsAllowed("/system/app/Foo/Foo.apk", ai))
        assertTrue(DexInjection.pathIsAllowed("/system/priv-app/Bar/Bar.apk", ai))
    }

    @Test
    fun `apex jars are allowed`() {
        val ai = appInfoFor()
        assertTrue(
            DexInjection.pathIsAllowed(
                "/apex/com.android.art/javalib/core-oj.jar",
                ai,
            ),
        )
    }

    @Test
    fun `dalvik-cache paths are allowed`() {
        val ai = appInfoFor()
        assertTrue(
            DexInjection.pathIsAllowed(
                "/data/dalvik-cache/arm64/system@framework@boot-framework.art",
                ai,
            ),
        )
    }

    @Test
    fun `data app path containing our package component is allowed`() {
        // Catches the dynamic-feature-module case where ApplicationInfo
        // hasn't been re-fetched yet but a new split lands under the
        // same /data/app/<pkg>-<hash>/ directory.
        val ai = appInfoFor()
        assertTrue(
            DexInjection.pathIsAllowed(
                "/data/app/com.example.app-XyZ123==/split_late.apk",
                ai,
            ),
        )
    }

    @Test
    fun `tmp paths are not allowed`() {
        val ai = appInfoFor()
        assertFalse(DexInjection.pathIsAllowed("/data/local/tmp/payload.dex", ai))
    }

    @Test
    fun `foreign packages data dir is not allowed`() {
        val ai = appInfoFor()
        assertFalse(
            DexInjection.pathIsAllowed(
                "/data/data/com.attacker.cnc/cache/payload.dex",
                ai,
            ),
        )
    }

    @Test
    fun `data app path for a different package is not allowed`() {
        val ai = appInfoFor()
        assertFalse(
            DexInjection.pathIsAllowed(
                "/data/app/com.attacker.app-Foo==/base.apk",
                ai,
            ),
        )
    }

    @Test
    fun `empty path is never allowed`() {
        val ai = appInfoFor()
        assertFalse(DexInjection.pathIsAllowed("", ai))
    }

    @Test
    fun `package name as substring of another path component is not a false positive`() {
        // Our pkg = com.example.app; an attacker drops a payload at
        // /data/app/com.example.appspoof-X/base.apk — the trailing
        // 'spoof' should make pathContainsPackageComponent reject it.
        val ai = appInfoFor()
        assertFalse(
            DexInjection.pathIsAllowed(
                "/data/app/com.example.appspoof-Foo==/base.apk",
                ai,
            ),
        )
    }

    // ---- classifyDalvikRegion -------------------------------------------

    private fun region(label: String) =
        MapsParser.DalvikAnonRegion(
            addressRange = "7090000000-7090001000",
            perms = "rw-p",
            label = label,
        )

    @Test
    fun `InMemoryDexClassLoader buffer source classifies as IN_MEMORY`() {
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region("anon:dalvik-classes.dex extracted in memory from <buffer>"),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.IN_MEMORY, verdict.kind)
        assertEquals("<buffer>", verdict.source)
    }

    @Test
    fun `extraction from app's own apk classifies as OWN_APK`() {
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region(
                "anon:dalvik-classes.dex extracted in memory from " +
                    "/data/app/com.example.app-AbCdEf==/base.apk",
            ),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.OWN_APK, verdict.kind)
    }

    @Test
    fun `extraction from system path classifies as OWN_APK`() {
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region(
                "anon:dalvik-classes.dex extracted in memory from " +
                    "/system/framework/core-libart.jar",
            ),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.OWN_APK, verdict.kind)
    }

    @Test
    fun `extraction from tmp path classifies as FOREIGN_PATH`() {
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region(
                "anon:dalvik-classes.dex extracted in memory from " +
                    "/data/local/tmp/payload.dex",
            ),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.FOREIGN_PATH, verdict.kind)
        assertEquals("/data/local/tmp/payload.dex", verdict.source)
    }

    @Test
    fun `extraction from foreign data dir classifies as FOREIGN_PATH`() {
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region(
                "anon:dalvik-classes.dex extracted in memory from " +
                    "/data/data/com.attacker.cnc/cache/payload.dex",
            ),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.FOREIGN_PATH, verdict.kind)
    }

    @Test
    fun `dalvik internals are NON_DEX`() {
        val ai = appInfoFor()
        for (label in listOf(
            "anon:dalvik-jit-code-cache",
            "anon:dalvik-zygote-claimed",
            "anon:dalvik-LinearAlloc",
            "anon:dalvik-non moving space",
        )) {
            val verdict = DexInjection.classifyDalvikRegion(region(label), ai)
            assertEquals("expected NON_DEX for $label", DexInjection.DalvikRegionKind.NON_DEX, verdict.kind)
        }
    }

    @Test
    fun `Android 14+ bare DEX data label classifies as IN_MEMORY_UNATTRIBUTED`() {
        // The exact label format observed on a Pixel 6 Pro running
        // Android 16 stock with InMemoryDexClassLoader injection
        // (validated on-device 2026-05-03). Earlier Android
        // releases emit the longer `extracted in memory from <src>`
        // form, but 14+ collapses every in-memory extraction to
        // this bare label with no source attribution.
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(region("anon:dalvik-DEX data"), ai)
        assertEquals(DexInjection.DalvikRegionKind.IN_MEMORY_UNATTRIBUTED, verdict.kind)
    }

    @Test
    fun `boot image art mappings classify as NON_DEX even though label starts with anon dalvik`() {
        // From the same maps dump:
        //   [anon:dalvik-/system/framework/boot-framework.art]
        // These exist on every Android process; classifying them
        // as DEX content would false-positive on every clean device.
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region("anon:dalvik-/system/framework/boot-framework.art"),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.NON_DEX, verdict.kind)
    }

    @Test
    fun `non-dalvik label classifies as UNKNOWN`() {
        // The parser is supposed to filter these out, but if a
        // caller passes one through anyway the classifier degrades
        // safely instead of escalating.
        val ai = appInfoFor()
        val verdict = DexInjection.classifyDalvikRegion(
            region("anon:libc_malloc"),
            ai,
        )
        assertEquals(DexInjection.DalvikRegionKind.UNKNOWN, verdict.kind)
    }
}
