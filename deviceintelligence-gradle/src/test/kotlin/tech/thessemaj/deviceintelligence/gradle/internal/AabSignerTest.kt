package tech.thessemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.jar.JarFile
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AabSignerTest {
    @Test fun signsAndVerifiesAsJar(@TempDir dir: File) {
        val keystore = File(System.getProperty("user.home"), ".android/debug.keystore")
        assumeTrue(keystore.isFile, "debug keystore not present; skipping AAB sign test")

        val ks = KeyStore.getInstance("PKCS12").runCatching {
            FileInputStream(keystore).use { load(it, "android".toCharArray()) }
            this
        }.getOrElse {
            KeyStore.getInstance("JKS").apply {
                FileInputStream(keystore).use { load(it, "android".toCharArray()) }
            }
        }
        val key = ks.getKey("androiddebugkey", "android".toCharArray()) as PrivateKey
        val certs = ks.getCertificateChain("androiddebugkey").map { it as X509Certificate }

        // Fixture zip with NO signature and NO directory entries.
        val aab = File(dir, "fixture.aab")
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/manifest/AndroidManifest.xml")); z.write("M".toByteArray()); z.closeEntry()
            z.putNextEntry(ZipEntry("base/assets/tech.thessemaj.deviceintelligence/fingerprint.bin"))
            z.write(byteArrayOf(1, 2, 3)); z.closeEntry()
        }

        AabSigner.sign(aab, key, certs)

        JarFile(aab, true).use { jf ->
            val names = jf.entries().toList().map { it.name }
            assertTrue(names.any { it == "META-INF/MANIFEST.MF" }, "manifest present")
            assertTrue(names.any { it.endsWith(".SF") }, ".SF present")
            assertTrue(names.any { it.endsWith(".RSA") || it.endsWith(".EC") || it.endsWith(".DSA") }, "sig block present")
            // Reading every entry fully forces JarFile to verify the v1 signature.
            for (e in jf.entries()) {
                if (e.isDirectory) continue
                jf.getInputStream(e).use { it.readBytes() }
            }
        }
    }
}
