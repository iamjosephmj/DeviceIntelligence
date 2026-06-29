package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkIntegrityDetectorBundleTest {

    private val certA = "aabbcc"
    private val certB = "ddeeff"
    private val entryName = "classes.dex"
    private val bakedHash = "deadbeef"

    // Case 1: cert in allow-set → no signer finding
    @Test
    fun `cert in allow-set produces no signer finding`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = listOf(certA),
            allowSet = setOf(certA),
            bundleEntryHashes = emptyMap(),
            resolveDecompressedHash = { null },
        )
        val findings = (eval as BundleEval.Ok).findings
        assertTrue(findings.none { it.kind == "apk_signer_mismatch" })
    }

    // Case 2: cert not in allow-set → apk_signer_mismatch CRITICAL
    @Test
    fun `cert not in allow-set emits apk_signer_mismatch CRITICAL`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = listOf(certB),
            allowSet = setOf(certA),
            bundleEntryHashes = emptyMap(),
            resolveDecompressedHash = { null },
        )
        val findings = (eval as BundleEval.Ok).findings
        assertEquals(1, findings.size)
        assertEquals("apk_signer_mismatch", findings[0].kind)
        assertEquals(Severity.CRITICAL, findings[0].severity)
    }

    // Case 3: empty allow-set → zero findings (fail-open)
    @Test
    fun `empty allow-set skips signer check and produces no findings`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = listOf(certB),
            allowSet = emptySet(),
            bundleEntryHashes = emptyMap(),
            resolveDecompressedHash = { null },
        )
        val findings = (eval as BundleEval.Ok).findings
        assertTrue(findings.isEmpty())
    }

    // Case 4: resolver returns null for all paths → apk_entry_removed HIGH
    @Test
    fun `resolver returning null emits apk_entry_removed HIGH`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = null,
            allowSet = emptySet(),
            bundleEntryHashes = mapOf(entryName to bakedHash),
            resolveDecompressedHash = { null },
        )
        val findings = (eval as BundleEval.Ok).findings
        assertEquals(1, findings.size)
        assertEquals("apk_entry_removed", findings[0].kind)
        assertEquals(Severity.HIGH, findings[0].severity)
    }

    // Case 5: resolver returns a mismatched hash → apk_entry_modified CRITICAL
    @Test
    fun `resolver returning mismatched hash emits apk_entry_modified CRITICAL`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = null,
            allowSet = emptySet(),
            bundleEntryHashes = mapOf(entryName to bakedHash),
            resolveDecompressedHash = { "00000000" },
        )
        val findings = (eval as BundleEval.Ok).findings
        assertEquals(1, findings.size)
        assertEquals("apk_entry_modified", findings[0].kind)
        assertEquals(Severity.CRITICAL, findings[0].severity)
    }

    // Case 6: resolver returns the matching hash → no finding
    @Test
    fun `resolver returning matching hash produces no finding`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = null,
            allowSet = emptySet(),
            bundleEntryHashes = mapOf(entryName to bakedHash),
            resolveDecompressedHash = { bakedHash },
        )
        val findings = (eval as BundleEval.Ok).findings
        assertTrue(findings.isEmpty())
    }

    // SignerUnavailable path: non-empty allow-set + null certs → SignerUnavailable
    @Test
    fun `null signer certs with non-empty allow-set returns SignerUnavailable`() {
        val eval = evaluateBundleIntegrity(
            observedSignerCerts = null,
            allowSet = setOf(certA),
            bundleEntryHashes = emptyMap(),
            resolveDecompressedHash = { null },
        )
        assertTrue(eval is BundleEval.SignerUnavailable)
    }
}
