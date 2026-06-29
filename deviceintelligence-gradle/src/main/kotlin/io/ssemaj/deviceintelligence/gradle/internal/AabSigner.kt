// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabSigner.kt
package io.ssemaj.deviceintelligence.gradle.internal

import jdk.security.jarsigner.JarSigner
import java.io.File
import java.io.FileOutputStream
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * JAR-signs (v1 / "JAR signing") a modified `.aab` so `bundletool validate`
 * and Play accept it after the plugin injects the bundle-mode fingerprint asset.
 *
 * Uses the JDK's in-process [JarSigner] (module `jdk.jartool`). The input
 * `.aab` must contain ONLY file entries — bundletool rejects directory entries.
 * [BundleIntegrityTask] is responsible for emitting a clean repack;
 * this signer copies entries through verbatim.
 *
 * Single-signer only (matching [InstrumentApkTask]).
 */
internal object AabSigner {

    fun sign(aab: File, key: PrivateKey, certs: List<X509Certificate>) {
        require(certs.isNotEmpty()) { "no signer certificates supplied for $aab" }
        val certPath = CertificateFactory.getInstance("X.509").generateCertPath(certs)
        val signer = JarSigner.Builder(key, certPath)
            .digestAlgorithm("SHA-256")
            .signerName("DI")
            .build()

        // JarSigner requires distinct input/output streams. Sign to a temp
        // sibling then atomically replace the original.
        val signed = File(aab.parentFile, "${aab.name}.signed")
        try {
            ZipFile(aab).use { zf ->
                FileOutputStream(signed).use { out -> signer.sign(zf, out) }
            }
            if (!signed.renameTo(aab)) {
                signed.copyTo(aab, overwrite = true)
                signed.delete()
            }
        } catch (t: Throwable) {
            signed.delete()
            throw t
        }
    }
}
