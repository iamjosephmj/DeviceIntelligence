package tech.thessemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AabHasherTest {
    @Test fun hashesDexAndSoNormalizingPaths(@TempDir dir: File) {
        val aab = File(dir, "x.aab")
        val dex = "DEXBYTES".toByteArray()
        val so = "SOBYTES".toByteArray()
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/dex/classes.dex")); z.write(dex); z.closeEntry()
            z.putNextEntry(ZipEntry("base/lib/arm64-v8a/libdicore.so")); z.write(so); z.closeEntry()
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("R".toByteArray()); z.closeEntry()
            z.putNextEntry(ZipEntry("base/manifest/AndroidManifest.xml")); z.write("M".toByteArray()); z.closeEntry()
        }
        val out = AabHasher.bundleEntryHashes(aab)
        assertEquals(setOf("classes.dex", "lib/arm64-v8a/libdicore.so"), out.keys)
        assertEquals(sha(dex), out["classes.dex"])
        assertEquals(sha(so), out["lib/arm64-v8a/libdicore.so"])
        assertTrue("resources.pb" !in out.keys)
    }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        .joinToString("") { "%02x".format(it) }
}
