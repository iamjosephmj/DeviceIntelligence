package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the testable seams of [RootIndicatorsDetector].
 *
 * The detector itself depends on a live `Context` and on filesystem
 * existence checks that can't be faked without Robolectric, so the
 * full integration is verified on-device (Pixel 6 Pro / Pixel 9
 * Pro). What we CAN test in pure JVM is:
 *  - The `/proc/mounts` parser pulls Magisk mount targets correctly.
 *  - The detector's stable identifiers (id, finding-kind constants)
 *    don't drift accidentally — these are the wire-contract surface
 *    backends key on, so they're worth pinning.
 */
class RootIndicatorsDetectorTest {

    @Test
    fun `detector id matches the F17 contract`() {
        assertEquals("F17.root_indicators", RootIndicatorsDetector.id)
    }

    @Test
    fun `parseMagiskMounts returns empty on a clean mount table`() {
        val mounts = """
            tmpfs /apex tmpfs rw,seclabel,nosuid,nodev,noexec 0 0
            /dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0
            /dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0
            none /sys/fs/cgroup cgroup2 rw,seclabel,nosuid,nodev,noexec 0 0
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseMagiskMounts(mounts)
        assertEquals(emptyList<String>(), hits)
    }

    @Test
    fun `parseMagiskMounts captures magisk-named mount target`() {
        val mounts = """
            tmpfs /apex tmpfs rw,seclabel 0 0
            magisk /sbin tmpfs rw,seclabel 0 0
            /dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseMagiskMounts(mounts)
        assertEquals(listOf("mount=/sbin"), hits)
    }

    @Test
    fun `parseMagiskMounts is case-insensitive on the magisk substring`() {
        val mounts = """
            MAGISK /sbin tmpfs rw,seclabel 0 0
            something /MagiskOverlay/bar overlay rw 0 0
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseMagiskMounts(mounts)
        assertEquals(
            listOf("mount=/sbin", "mount=/MagiskOverlay/bar"),
            hits,
        )
    }

    @Test
    fun `parseMagiskMounts handles multiple matching lines`() {
        val mounts = """
            tmpfs /apex tmpfs rw,seclabel 0 0
            magisk /sbin tmpfs rw,seclabel 0 0
            magisk /system/bin tmpfs rw,seclabel 0 0
            magisk /system/etc tmpfs rw,seclabel 0 0
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseMagiskMounts(mounts)
        assertEquals(3, hits.size)
        assertTrue(hits.contains("mount=/sbin"))
        assertTrue(hits.contains("mount=/system/bin"))
        assertTrue(hits.contains("mount=/system/etc"))
    }

    @Test
    fun `parseMagiskMounts skips lines without a target column`() {
        // Malformed line with no target — we must not crash and must
        // not synthesize a bogus descriptor.
        val mounts = "magisk\n"

        val hits = RootIndicatorsDetector.parseMagiskMounts(mounts)
        assertEquals(emptyList<String>(), hits)
    }

    @Test
    fun `parseMagiskMounts handles empty input gracefully`() {
        assertEquals(emptyList<String>(), RootIndicatorsDetector.parseMagiskMounts(""))
    }
}
