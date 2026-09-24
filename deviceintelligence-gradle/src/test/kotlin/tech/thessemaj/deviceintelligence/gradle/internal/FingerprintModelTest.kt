package tech.thessemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class FingerprintModelTest {
    @Test fun bundleDefaultsAreOffAndSchemaIs3() {
        assertEquals(3, Fingerprint.SCHEMA_VERSION)
        val fp = minimalFp()
        assertFalse(fp.bundleMode)
        assertEquals(emptyMap<String, String>(), fp.bundleEntryHashes)
    }
    @Test fun bundleFieldsRoundTripThroughConstructor() {
        val fp = minimalFp().copy(bundleMode = true, bundleEntryHashes = mapOf("classes.dex" to "ab"))
        assertEquals(true, fp.bundleMode)
        assertEquals("ab", fp.bundleEntryHashes["classes.dex"])
    }
    private fun minimalFp() = Fingerprint(
        schemaVersion = Fingerprint.SCHEMA_VERSION, builtAtEpochMs = 0L, pluginVersion = "x",
        variantName = "release", applicationId = "a.b", signerCertSha256 = emptyList(),
        entries = emptyMap(), ignoredEntries = emptyList(), ignoredEntryPrefixes = emptyList(),
        expectedSourceDirPrefix = "/data/app/", expectedInstallerWhitelist = emptyList(),
    )
}
