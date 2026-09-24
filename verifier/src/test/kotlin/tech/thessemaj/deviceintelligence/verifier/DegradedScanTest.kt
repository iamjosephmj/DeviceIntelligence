package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/**
 * Degraded scans: the tokens a device emits when it could not bind itself.
 *
 * The point of the whole feature is that suppressing the SDK must not be cheaper
 * than defeating it. A hook that breaks initialize() or setSession() used to buy
 * silence, and silence at the backend is indistinguishable from a network error or
 * an app that never integrated. Now the device emits a token that names its own
 * missing binding and carries the detector findings anyway.
 *
 * Two properties are load-bearing and asserted throughout:
 *   - a degraded token is NEVER authentic (it is unauthenticated by construction,
 *     so anyone able to encrypt to the server key can mint one), and
 *   - it still carries its signals, because a rejected token is exactly the
 *     telemetry the backend most wants.
 */
class DegradedScanTest {

    private val server = TestV2.serverKeyPair()
    private val sessionId = "a".repeat(64)

    /** A signed_content document with the given attestation block and signals. */
    private fun doc(
        reason: String,
        level: String = "NONE",
        signed: String = "NONE",
        detail: String? = null,
        signals: String = """[{"id":"INTEL_0001","severity":"CRITICAL","detail":"art hook"}]""",
        sid: String = sessionId,
    ) = """{"schemaVersion":4,"type":"scan","sessionId":"$sid","name":"checkout",""" +
        """"ts":1787670292,"bootstrap":false,""" +
        """"app":{"package":"tech.thessemaj.deviceintelligence.sample","signer":"${"aa".repeat(32)}"},""" +
        """"device":{"api":36,"abi":"arm64-v8a","model":"Pixel 6 Pro"},""" +
        """"signals":$signals,""" +
        """"attestation":{"level":"$level","signed":"$signed","reason":"$reason"""" +
        (detail?.let { ""","detail":"$it"""" } ?: "") + "}}"

    /** The wire shape of a degraded token: binding present, SIG line empty. */
    private fun token(body: String, sig: String = "") =
        TestV2.encryptForTest("$body\n--BINDING\nSIG$sig", server.public)

    private fun verify(t: String, session: ScanSession? = null) =
        ScanVerifier().verifyScan(t, sessionId, server.private, session)

    // --- the core contract ---------------------------------------------------

    @Test fun a_degraded_token_is_never_authentic() {
        val r = verify(token(doc("KEYGEN_FAILED")))
        assertFalse("an unauthenticated token must never read as genuine", r.ok)
        assertFalse(r.deviceIntegrityOk)
    }

    @Test fun a_degraded_token_still_carries_its_signals() {
        // The whole point: the failure now arrives WITH its evidence. Before this,
        // every early rejection returned an empty signal list and the backend was
        // blinded to exactly the cases it most wants to see.
        val r = verify(token(doc("KEYGEN_FAILED")))
        assertTrue("the detector findings must survive the rejection",
            r.signals.any { it.id == "INTEL_0001" })
    }

    @Test fun the_attestation_block_is_reported() {
        val r = verify(token(doc("KEYGEN_FAILED", detail = "strongbox_unavailable:-68")))
        val a = assertNotNull("the attestation block must be surfaced", r.attestation).let { r.attestation!! }
        assertEquals(AttestationLevel.NONE, a.level)
        assertEquals(AttestationLevel.NONE, a.signed)
        assertEquals("KEYGEN_FAILED", a.reason)
        assertEquals("strongbox_unavailable:-68", a.detail)
        assertTrue("a token with no attested binding is degraded", a.degraded)
    }

    @Test fun the_reason_reaches_the_caller() {
        assertTrue(verify(token(doc("NO_SESSION"))).reason!!.contains("NO_SESSION"))
        assertTrue(verify(token(doc("LICENCE_EXPIRED"))).reason!!.contains("LICENCE_EXPIRED"))
    }

    // --- the software rung ---------------------------------------------------

    @Test fun a_software_signed_token_is_still_not_authentic() {
        // SOFTWARE gives the backend continuity across one process's degraded scans.
        // It is not evidence: a non-attested key proves nothing about the device.
        val r = verify(token(doc("KEYGEN_FAILED", level = "SOFTWARE", signed = "SOFTWARE"),
            sig = "aa".repeat(32)))
        assertFalse("a software key is not a hardware root of trust", r.ok)
        assertEquals(AttestationLevel.SOFTWARE, r.attestation?.signed)
    }

    // --- containment: a degraded token must not become a denial-of-service ----

    @Test fun a_degraded_token_cannot_downgrade_an_established_session() {
        // Degraded tokens are cheap to forge, so if one could revoke the session it
        // names, an attacker could lock out other users by minting them against
        // observed session ids. The established facts must survive untouched.
        val established = ScanSession(
            attestedKey = "3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb",
            attestedApp = null,
            assurance = Assurance.STRONGBOX,
            bootState = "Verified",
            deviceLocked = true,
        )
        val r = verify(token(doc("KEYGEN_FAILED")), established)

        assertFalse("still rejected", r.ok)
        assertSame("the established session must be returned untouched, not replaced",
            established, r.session)
        assertTrue("the regression is itself worth reporting",
            r.signals.any { it.id == "INTEL_0052" })
    }

    @Test fun a_degraded_token_never_establishes_a_session() {
        // The mirror of the above: nothing unattested may CREATE trust either.
        assertNull("an unattested token cannot establish session facts",
            verify(token(doc("NO_SESSION"))).session)
    }

    // --- the gates that still apply -----------------------------------------

    @Test fun a_degraded_token_naming_another_session_is_rejected_for_being_degraded() {
        // Both gates fail, and the DEGRADATION is the primary fact: the token is
        // unauthenticated whichever session it names, so that is the reason reported.
        // The mismatch is still recorded, so the audit trail keeps both.
        val r = ScanVerifier().verifyScan(
            token(doc("KEYGEN_FAILED", sid = "b".repeat(64))), sessionId, server.private)
        assertFalse(r.ok)
        assertTrue(r.reason!!.contains("KEYGEN_FAILED"))
        assertFalse(r.checks.first { it.name == "session id matches issued" }.ok)
    }

    @Test fun an_ATTESTED_token_for_another_session_still_fails_on_the_mismatch() {
        // The ordering above must not weaken the session gate for genuine tokens.
        val r = ScanVerifier().verifyScan(
            token(doc("OK", level = "ATTESTED", signed = "ATTESTED", sid = "b".repeat(64)),
                sig = "aa".repeat(32)), sessionId, server.private)
        assertFalse(r.ok)
        assertEquals("session id mismatch", r.reason)
    }

    @Test fun a_no_session_token_reports_the_degradation_not_the_mismatch() {
        // Measured on the reference device: a scan with no prepared session carries
        // sessionId="" and so ALSO fails the session-id gate. The mismatch is a
        // SYMPTOM of the degradation, and reporting it as the reason buried the real
        // story and skipped the degradation signals entirely.
        val r = verify(token(doc("NO_SESSION", sid = "")))
        assertFalse(r.ok)
        assertTrue("the degradation is the reason, not the mismatch",
            r.reason!!.contains("NO_SESSION"))
        assertTrue("INTEL_0053 must still be raised", r.signals.any { it.id == "INTEL_0053" })
        assertFalse("the mismatch is still recorded as a failed check",
            r.checks.first { it.name == "session id matches issued" }.ok)
    }

    @Test fun a_healthy_scan_is_not_treated_as_degraded() {
        // The attestation block rides on EVERY scan, so a field that only appeared on
        // degradation would be a field an attacker strips. OK must stay OK.
        val r = verify(token(doc("OK", level = "ATTESTED", signed = "ATTESTED")))
        assertFalse("an attested claim is not degraded", r.attestation!!.degraded)
        assertEquals("OK", r.attestation!!.reason)
    }

    @Test fun a_token_with_no_attestation_block_is_still_read() {
        // An older device predates the block entirely. It is not degraded-by-absence;
        // it is simply an older client, and the existing gates judge it.
        val old = """{"schemaVersion":4,"type":"scan","sessionId":"$sessionId",""" +
            """"name":"checkout","ts":1787670292,"bootstrap":false,"signals":[]}"""
        val r = verify(token(old, sig = "aa".repeat(32)))
        assertNull("no block means no claim, not a degraded claim", r.attestation)
    }
}
