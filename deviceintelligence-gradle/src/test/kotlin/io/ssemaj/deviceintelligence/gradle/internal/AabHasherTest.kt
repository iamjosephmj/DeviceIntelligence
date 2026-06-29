package io.ssemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AabHasherTest {

    @Test fun normalizesPathsAndHashesDecompressedBytes(@TempDir dir: File) {
        val dex = "DEXBYTES_UNIQUE_CONTENT_12345".toByteArray()
        val so  = "SOBYTES_UNIQUE_CONTENT_67890".toByteArray()
        val aab = File(dir, "app.aab")

        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/dex/classes.dex")); z.write(dex); z.closeEntry()
            z.putNextEntry(ZipEntry("base/dex/classes2.dex")); z.write("C2".toByteArray()); z.closeEntry()
            z.putNextEntry(ZipEntry("base/lib/arm64-v8a/libdicore.so")); z.write(so); z.closeEntry()
            // These must be excluded:
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("RESOURCES".toByteArray()); z.closeEntry()
            z.putNextEntry(ZipEntry("base/manifest/AndroidManifest.xml")); z.write("XML".toByteArray()); z.closeEntry()
        }

        val result = AabHasher.bundleEntryHashes(aab)

        // Entry names use installed-APK keys, not bundle keys.
        assertEquals(
            setOf("classes.dex", "classes2.dex", "lib/arm64-v8a/libdicore.so"),
            result.keys,
        )
        // Hash is the decompressed (inflated) SHA-256.
        assertEquals(sha256Hex(dex), result["classes.dex"])
        assertEquals(sha256Hex(so),  result["lib/arm64-v8a/libdicore.so"])
        // Resources and manifest are excluded.
        assertFalse("base/resources.pb" in result.keys)
        assertFalse("resources.pb" in result.keys)
    }

    @Test fun emptyAabProducesEmptyMap(@TempDir dir: File) {
        val aab = File(dir, "empty.aab")
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("R".toByteArray()); z.closeEntry()
        }
        assertEquals(emptyMap<String, String>(), AabHasher.bundleEntryHashes(aab))
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}
