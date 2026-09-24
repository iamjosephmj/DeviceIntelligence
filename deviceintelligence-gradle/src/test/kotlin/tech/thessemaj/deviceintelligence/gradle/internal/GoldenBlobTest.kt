package tech.thessemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * Emits the deterministic v3 bundle-mode blob consumed by the native fingerprint
 * fuzz/parity harness (`fuzz_fingerprint.cpp`). The corpus file layout mirrors what
 * that harness expects: `[selector byte][key bytes][cipher]` where the harness
 * derives `klen = selector % 32 + 1`. We pin `selector = 0x00` (klen = 1) and a
 * single-byte XOR key so the file is self-contained and the native decoder, after
 * XOR + parse, yields `bundle_mode = true` with exactly two bundle entries.
 */
class GoldenBlobTest {
    @Test fun emitV3Golden() {
        val fp = Fingerprint(
            schemaVersion = 3, builtAtEpochMs = 0L, pluginVersion = "golden",
            variantName = "release", applicationId = "tech.thessemaj.deviceintelligence.golden", signerCertSha256 = listOf("ab"),
            entries = emptyMap(), ignoredEntries = emptyList(), ignoredEntryPrefixes = listOf("META-INF/"),
            expectedSourceDirPrefix = "/data/app/", expectedInstallerWhitelist = emptyList(),
            dicoreTextSha256ByAbi = mapOf("arm64-v8a" to "00"),
            bundleMode = true,
            bundleEntryHashes = mapOf("classes.dex" to "11", "lib/arm64-v8a/libdicore.so" to "22"),
        )
        val plain = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()

        val selector = 0x00.toByte() // klen = (0 % 32) + 1 = 1
        val key = 0x5a.toByte()
        val out = ByteArray(2 + plain.size)
        out[0] = selector
        out[1] = key
        for (i in plain.indices) out[2 + i] = (plain[i].toInt() xor key.toInt()).toByte()

        val target = File(System.getProperty("golden.out") ?: "build/valid_v3_bundle.bin")
        target.parentFile?.mkdirs()
        target.writeBytes(out)
    }
}
