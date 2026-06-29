package io.ssemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class FingerprintCodecTest {

    /** A v3 bundle-mode fingerprint round-trips through encode → decode. */
    @Test fun bundleModeRoundTrip() {
        val fp = baseFingerprint().copy(
            bundleMode = true,
            bundleEntryHashes = mapOf(
                "classes.dex" to "aabbccddeeff0011",
                "lib/arm64-v8a/libdicore.so" to "00112233445566778899",
            ),
        )
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))

        assertEquals(true, back.bundleMode)
        assertEquals(fp.bundleEntryHashes, back.bundleEntryHashes)
        assertEquals(3, FingerprintCodec.FORMAT_VERSION)
    }

    /** A v3 APK-mode fingerprint (bundleMode=false) also round-trips. */
    @Test fun apkModeRoundTripStillWorks() {
        val fp = baseFingerprint() // bundleMode=false by default
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))

        assertEquals(false, back.bundleMode)
        assertEquals(emptyMap<String, String>(), back.bundleEntryHashes)
        assertEquals("release", back.variantName)
    }

    /** bundleEntryHashes keys are sorted on encode; order is stable. */
    @Test fun bundleEntryHashesSortedOnEncode() {
        val fp = baseFingerprint().copy(
            bundleMode = true,
            bundleEntryHashes = mapOf(
                "lib/arm64-v8a/libfoo.so" to "cc",
                "classes.dex" to "aa",
                "classes2.dex" to "bb",
            ),
        )
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))

        // Sorted order: classes.dex, classes2.dex, lib/arm64-v8a/libfoo.so
        val keys = back.bundleEntryHashes.keys.toList()
        assertEquals(listOf("classes.dex", "classes2.dex", "lib/arm64-v8a/libfoo.so"), keys)
    }

    private fun baseFingerprint() = Fingerprint(
        schemaVersion = Fingerprint.SCHEMA_VERSION,
        builtAtEpochMs = 1_000_000L,
        pluginVersion = "5.0.0",
        variantName = "release",
        applicationId = "io.ssemaj.sample",
        signerCertSha256 = listOf("deadbeef01234567"),
        entries = mapOf("classes.dex" to "hash0"),
        ignoredEntries = listOf("assets/io.ssemaj.deviceintelligence/fingerprint.bin"),
        ignoredEntryPrefixes = listOf("META-INF/"),
        expectedSourceDirPrefix = "/data/app/",
        expectedInstallerWhitelist = emptyList(),
        nativeLibInventoryByAbi = mapOf("arm64-v8a" to listOf("libdicore.so")),
        dicoreTextSha256ByAbi = mapOf("arm64-v8a" to "texthash"),
    )
}
