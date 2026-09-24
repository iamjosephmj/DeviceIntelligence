package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The consistent Play-Integrity-Fix buster: self-reported boot vs hardware attestation. */
class BootStateSpooferTest {
    private fun att(boot: Int?, locked: Boolean?) = AttestationFields(securityLevel = 2, verifiedBootState = boot, deviceLocked = locked)

    @Test fun flags_spoofer_props_clean_attestation_dirty() {
        // IntegrityBox: props forced green/locked, TEE says Unverified/unlocked.
        val reported = mapOf<String, Any?>("vbs" to "green", "blocked" to "1", "vbmeta" to "locked")
        assertTrue(EnrollVerifier.bootStateSpoofer(reported, att(2 /*Unverified*/, false)))
    }

    @Test fun flags_spoofer_via_locked_props_without_green() {
        // The live Pixel case: verifiedbootstate blank, but flash.locked=1 / vbmeta=locked
        // while hardware attestation says Unverified/unlocked -> still a contradiction.
        val reported = mapOf<String, Any?>("vbs" to "", "blocked" to "1", "vbmeta" to "locked")
        assertTrue(EnrollVerifier.bootStateSpoofer(reported, att(2 /*Unverified*/, false)))
    }

    @Test fun flags_spoofer_via_vbmeta_only() {
        val reported = mapOf<String, Any?>("vbs" to "green", "blocked" to "", "vbmeta" to "locked")
        assertTrue(EnrollVerifier.bootStateSpoofer(reported, att(3 /*Failed*/, false)))
    }

    @Test fun passes_genuine_locked_device() {
        // Consistent: props green/locked AND attestation Verified/locked.
        val reported = mapOf<String, Any?>("vbs" to "green", "blocked" to "1", "vbmeta" to "locked")
        assertFalse(EnrollVerifier.bootStateSpoofer(reported, att(0 /*Verified*/, true)))
    }

    @Test fun does_not_flag_plain_unlocked_device() {
        // Honest unlocked dev device: props orange/unlocked, attestation Unverified/unlocked.
        val reported = mapOf<String, Any?>("vbs" to "orange", "blocked" to "0", "vbmeta" to "unlocked")
        assertFalse(EnrollVerifier.bootStateSpoofer(reported, att(2, false)))
    }

    @Test fun no_self_report_is_not_flagged() {
        assertFalse(EnrollVerifier.bootStateSpoofer(emptyMap(), att(0, true)))
        assertFalse(EnrollVerifier.bootStateSpoofer(emptyMap(), att(2, false)))
    }

    @Test fun clean_claim_with_no_attestation_is_flagged() {
        // Claims green/locked but provides no usable attestation RootOfTrust -> spoof.
        val reported = mapOf<String, Any?>("vbs" to "green", "blocked" to "1")
        assertTrue(EnrollVerifier.bootStateSpoofer(reported, null))
    }
}
