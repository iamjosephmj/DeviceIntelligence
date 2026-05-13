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
        assertEquals("runtime.root", RootIndicatorsDetector.id)
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

    // ---- parseInitMountinfo (Shamiko-bypass cross-check) ------------------

    @Test
    fun `parseInitMountinfo returns empty on a clean init mount namespace`() {
        val mountinfo = """
            1 0 253:0 / / rw,relatime shared:1 - ext4 /dev/root rw,errors=continue
            17 1 0:18 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw,seclabel
            18 1 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseInitMountinfo(mountinfo)
        assertEquals(emptyList<String>(), hits)
    }

    @Test
    fun `parseInitMountinfo captures magisk-named mount in PID 1 namespace`() {
        val mountinfo = """
            1 0 253:0 / / rw,relatime shared:1 - ext4 /dev/root rw,errors=continue
            42 1 0:99 / /sbin rw,nosuid,relatime shared:33 - tmpfs magisk rw,size=10240k,mode=755
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseInitMountinfo(mountinfo)
        // mountpoint is the 5th space-separated field
        assertEquals(listOf("mountpoint=/sbin"), hits)
    }

    @Test
    fun `parseInitMountinfo is case-insensitive on the magisk substring`() {
        val mountinfo = """
            42 1 0:99 / /MagiskOverlay rw,nosuid - tmpfs MAGISK rw,size=10240k
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseInitMountinfo(mountinfo)
        assertEquals(listOf("mountpoint=/MagiskOverlay"), hits)
    }

    @Test
    fun `parseInitMountinfo handles multiple matching lines`() {
        val mountinfo = """
            42 1 0:99 / /sbin rw - tmpfs magisk rw
            43 1 0:99 / /system/bin rw - tmpfs magisk rw
            44 1 0:99 / /system/etc rw - tmpfs magisk rw
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseInitMountinfo(mountinfo)
        assertEquals(3, hits.size)
        assertTrue(hits.contains("mountpoint=/sbin"))
        assertTrue(hits.contains("mountpoint=/system/bin"))
        assertTrue(hits.contains("mountpoint=/system/etc"))
    }

    @Test
    fun `parseInitMountinfo handles empty input gracefully`() {
        assertEquals(emptyList<String>(), RootIndicatorsDetector.parseInitMountinfo(""))
    }

    // ---- parseMagiskDaemonSocket -----------------------------------------

    @Test
    fun `parseMagiskDaemonSocket returns false on a clean unix socket table`() {
        val unix = """
            Num       RefCount Protocol Flags    Type St Inode Path
            ffffaa00  2        0        10000    0001 01    123 /dev/socket/zygote
            ffffaa10  2        0        10000    0001 01    456 @android_logger
        """.trimIndent()

        assertEquals(false, RootIndicatorsDetector.parseMagiskDaemonSocket(unix))
    }

    @Test
    fun `parseMagiskDaemonSocket trips on @magisk_daemon entry`() {
        val unix = """
            Num       RefCount Protocol Flags    Type St Inode Path
            ffffaa00  2        0        10000    0001 01    123 /dev/socket/zygote
            ffffbb20  3        0        10000    0001 01    789 @magisk_daemon
        """.trimIndent()

        assertEquals(true, RootIndicatorsDetector.parseMagiskDaemonSocket(unix))
    }

    @Test
    fun `parseMagiskDaemonSocket handles empty input gracefully`() {
        assertEquals(false, RootIndicatorsDetector.parseMagiskDaemonSocket(""))
    }

    // ---- parseConscryptTmpfsMount (TLS-MITM enablement) -------------------

    @Test
    fun `parseConscryptTmpfsMount returns empty on a clean mount namespace`() {
        val mountinfo = """
            1 0 253:0 / / rw,relatime shared:1 - ext4 /dev/root rw,errors=continue
            22 17 0:35 / /apex/com.android.conscrypt ro,nosuid,nodev,relatime shared:14 - ext4 /dev/block/dm-7 ro,seclabel
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseConscryptTmpfsMount(mountinfo)
        // Legitimate ext4-backed conscrypt APEX — NOT flagged.
        assertEquals(emptyList<String>(), hits)
    }

    @Test
    fun `parseConscryptTmpfsMount trips on tmpfs over apex conscrypt`() {
        val mountinfo = """
            1 0 253:0 / / rw,relatime shared:1 - ext4 /dev/root rw,errors=continue
            99 17 0:42 / /apex/com.android.conscrypt rw,nosuid,relatime shared:88 - tmpfs tmpfs rw,size=8192k,mode=755
        """.trimIndent()

        val hits = RootIndicatorsDetector.parseConscryptTmpfsMount(mountinfo)
        assertEquals(listOf("mountpoint=/apex/com.android.conscrypt"), hits)
    }

    @Test
    fun `parseConscryptTmpfsMount does not trip on non-tmpfs conscrypt mounts`() {
        // Some MagiskTrustUserCerts variants overlay using a non-tmpfs
        // source. We're strict on `tmpfs` to avoid false-positives on
        // legitimate erofs/ext4-backed conscrypt remounts during system
        // updates. False-negative on exotic source types is acceptable;
        // the runtime hook layers catch the broader compromise.
        val mountinfo = """
            99 17 0:42 / /apex/com.android.conscrypt rw,nosuid - overlay overlay rw
        """.trimIndent()

        assertEquals(emptyList<String>(), RootIndicatorsDetector.parseConscryptTmpfsMount(mountinfo))
    }

    @Test
    fun `parseConscryptTmpfsMount ignores lines without a dash separator`() {
        // Defensive — malformed `mountinfo` lines lacking the ` - `
        // separator should be skipped, not crashed on.
        val mountinfo = "this line has /apex/com.android.conscrypt but no dash separator\n"

        assertEquals(emptyList<String>(), RootIndicatorsDetector.parseConscryptTmpfsMount(mountinfo))
    }

    @Test
    fun `parseConscryptTmpfsMount handles empty input gracefully`() {
        assertEquals(emptyList<String>(), RootIndicatorsDetector.parseConscryptTmpfsMount(""))
    }
}
