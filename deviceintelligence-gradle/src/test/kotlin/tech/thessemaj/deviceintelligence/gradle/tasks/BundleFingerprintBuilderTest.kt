package tech.thessemaj.deviceintelligence.gradle.tasks

import tech.thessemaj.deviceintelligence.baker.DeviceIntelligenceBaker
import tech.thessemaj.deviceintelligence.gradle.internal.FingerprintCodec
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BundleFingerprintBuilderTest {
    @Test fun bakedBlobDecodesToBundleModeWithMergedSigners(@TempDir dir: File) {
        val dex = "DEXBYTES".toByteArray()
        val so = "SOBYTES".toByteArray()
        val aab = File(dir, "app.aab")
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/dex/classes.dex")); z.write(dex); z.closeEntry()
            z.putNextEntry(ZipEntry("base/lib/arm64-v8a/libother.so")); z.write(so); z.closeEntry()
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("R".toByteArray()); z.closeEntry()
        }

        val blob = BundleFingerprintBuilder.build(
            aab = aab,
            signerCertHashes = listOf("aa11"),
            playPins = listOf("bb22", "aa11"), // overlap must de-dupe
            pluginVersion = "1.9.0",
            variant = "release",
            appId = "tech.thessemaj.deviceintelligence.sample",
        )

        // Envelope: seed(32) ‖ XOR(ciphertext, DeviceIntelligenceBaker.fpKey(seed)).
        val seed = blob.copyOfRange(0, 32)
        val key = DeviceIntelligenceBaker.fpKey(seed)
        val plain = ByteArray(blob.size - 32)
        for (i in plain.indices) plain[i] = (blob[32 + i].toInt() xor key[i % 32].toInt()).toByte()

        val fp = FingerprintCodec.decode(ByteArrayInputStream(plain))
        assertEquals(true, fp.bundleMode)
        assertEquals(sha(dex), fp.bundleEntryHashes["classes.dex"])
        assertEquals(sha(so), fp.bundleEntryHashes["lib/arm64-v8a/libother.so"])
        assertTrue("base/resources.pb" !in fp.bundleEntryHashes.keys)
        // Merged + de-duplicated signer allow-set.
        assertEquals(setOf("aa11", "bb22"), fp.signerCertSha256.toSet())
        assertEquals("tech.thessemaj.deviceintelligence.sample", fp.applicationId)
    }

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
        .joinToString("") { "%02x".format(it) }
}
