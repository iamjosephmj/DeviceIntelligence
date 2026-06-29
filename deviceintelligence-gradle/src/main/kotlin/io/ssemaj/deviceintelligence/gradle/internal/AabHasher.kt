// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasher.kt
package io.ssemaj.deviceintelligence.gradle.internal

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Reads an Android App Bundle (`.aab`) and returns the SHA-256 of the
 * DECOMPRESSED body of every `classes*.dex` and `.so` entry under `lib/<abi>/`
 * in the base module, keyed by the APK-relative path the runtime sees on-device:
 *
 *   `base/dex/classes.dex`             → `classes.dex`
 *   `base/lib/arm64-v8a/libdicore.so`  → `lib/arm64-v8a/libdicore.so`
 *
 * We hash the decompressed bytes (not the compressed body, as APK mode does)
 * because Play re-encodes split APKs during delivery — only the inflated
 * payload is stable between build time and the installed device.
 *
 * Resources and the manifest are intentionally excluded: they are covered
 * transitively by the signer pin, and Play rewrites `resources.pb` to binary
 * `resources.arsc` so a byte hash would never match.
 */
internal object AabHasher {

    fun bundleEntryHashes(aab: File): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        ZipFile(aab).use { zf ->
            val entries = zf.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                if (e.isDirectory) continue
                val apkPath = when {
                    e.name.startsWith("base/dex/") && e.name.endsWith(".dex") ->
                        e.name.removePrefix("base/dex/")          // classes.dex
                    e.name.startsWith("base/lib/") && e.name.endsWith(".so") ->
                        e.name.removePrefix("base/")              // lib/<abi>/<file>.so
                    else -> null
                } ?: continue

                val md = MessageDigest.getInstance("SHA-256")
                // ZipFile.getInputStream yields the DECOMPRESSED bytes regardless of
                // the entry's compression method — this is what we want.
                zf.getInputStream(e).use { ins ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = ins.read(buf)
                        if (n < 0) break
                        md.update(buf, 0, n)
                    }
                }
                out[apkPath] = md.digest().joinToString("") { b -> "%02x".format(b) }
            }
        }
        return out
    }
}
