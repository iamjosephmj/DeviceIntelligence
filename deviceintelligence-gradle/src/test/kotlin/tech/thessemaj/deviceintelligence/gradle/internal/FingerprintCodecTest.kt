package tech.thessemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class FingerprintCodecTest {
    @Test fun bundleRoundTrip() {
        val fp = base().copy(
            bundleMode = true,
            bundleEntryHashes = mapOf("classes.dex" to "aa", "lib/arm64-v8a/libdicore.so" to "bb"),
        )
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))
        assertEquals(true, back.bundleMode)
        assertEquals(fp.bundleEntryHashes, back.bundleEntryHashes)
        assertEquals(FingerprintCodec.FORMAT_VERSION, 3)
    }

    @Test fun apkModeStillRoundTrips() {
        val fp = base()
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))
        assertEquals(false, back.bundleMode)
        assertEquals(emptyMap<String, String>(), back.bundleEntryHashes)
    }

    private fun base() = Fingerprint(
        schemaVersion = Fingerprint.SCHEMA_VERSION, builtAtEpochMs = 7L, pluginVersion = "1.9.0",
        variantName = "release", applicationId = "a.b", signerCertSha256 = listOf("c0"),
        entries = mapOf("x" to "y"), ignoredEntries = listOf("i"), ignoredEntryPrefixes = listOf("META-INF/"),
        expectedSourceDirPrefix = "/data/app/", expectedInstallerWhitelist = emptyList(),
        nativeLibInventoryByAbi = mapOf("arm64-v8a" to listOf("libdicore.so")),
        dicoreTextSha256ByAbi = mapOf("arm64-v8a" to "deadbeef"),
    )
}
