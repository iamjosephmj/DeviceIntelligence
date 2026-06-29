package io.ssemaj.deviceintelligence.gradle.tasks

import io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BundleFingerprintBuilderTest {

    @Test fun blobDecodesToBundleModeWithMergedSigners(@TempDir dir: File) {
        val dex = "DEXBYTES".toByteArray()
        val so  = "SOBYTES".toByteArray()
        val aab = File(dir, "app.aab")
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/dex/classes.dex")); z.write(dex); z.closeEntry()
            z.putNextEntry(ZipEntry("base/lib/arm64-v8a/libother.so")); z.write(so); z.closeEntry()
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("R".toByteArray()); z.closeEntry()
        }

        val key = ByteArray(32) { it.toByte() } // deterministic test key

        val blob = BundleFingerprintBuilder.build(
            aab = aab,
            key = key,
            signerCertHashes = listOf("aa11"),
            playPins = listOf("bb22", "aa11"), // overlap must be de-duplicated
            pluginVersion = "5.0.0",
            variant = "release",
            appId = "io.ssemaj.sample",
        )

        // Decrypt: XOR with the same key.
        val plain = ByteArray(blob.size) { i -> (blob[i].toInt() xor key[i % 32].toInt()).toByte() }
        val fp = FingerprintCodec.decode(ByteArrayInputStream(plain))

        assertTrue(fp.bundleMode)
        assertEquals(sha256Hex(dex), fp.bundleEntryHashes["classes.dex"])
        assertEquals(sha256Hex(so),  fp.bundleEntryHashes["lib/arm64-v8a/libother.so"])
        assertFalse("base/resources.pb" in fp.bundleEntryHashes.keys)
        // De-duplicated merged signer allow-set.
        assertEquals(setOf("aa11", "bb22"), fp.signerCertSha256.toSet())
        assertEquals("io.ssemaj.sample", fp.applicationId)
        // APK-mode entries is empty in bundle mode.
        assertTrue(fp.entries.isEmpty())
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}
