package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

class ScanVerifierTest {
    // 2026-08-01T00:00:00Z. Staleness must not depend on when the suite runs.
    private val sv = ScanVerifier(now = { 1785542400L })
    private val kp = TestV2.serverKeyPair()
    private val priv get() = kp.private

    private fun scanJson(sessionId: String, bootstrap: Boolean, attestedKey: String = "00") =
        """{"schemaVersion":4,"type":"scan","sessionId":"$sessionId","name":"checkout",""" +
        """"ts":1,"bootstrap":$bootstrap""" +
        (if (bootstrap) ""","attestedKey":"$attestedKey"""" else "") +
        ""","app":{"package":"com.example.app","signer":"${"aa".repeat(32)}"},""" +
        """"device":{"api":36,"abi":"arm64-v8a","model":"X"},"signals":[]}"""

    private fun token(json: String, binding: String) =
        TestV2.encryptForTest("$json\n--BINDING\n$binding", kp.public)

    @Test fun a_v1_token_is_rejected_on_the_scan_path() {
        // A downgrade to the baked-key envelope must not be accepted just because it decodes.
        val v1 = Hex.encode(Keystream.decrypt("anything".toByteArray()))
        val r = sv.verifyScan(v1, "s1", priv)
        assertFalse(r.ok)
        assertEquals("not a v2 token", r.reason)
    }

    @Test fun a_token_encrypted_to_another_key_does_not_open() {
        val other = TestV2.serverKeyPair()
        val t = TestV2.encryptForTest(scanJson("s1", true) + "\n--BINDING\nCERTdead", other.public)
        val r = sv.verifyScan(t, "s1", priv)
        assertFalse(r.ok)
        assertEquals("envelope did not open", r.reason)
    }

    @Test fun an_unbound_token_is_rejected() {
        val t = TestV2.encryptForTest(scanJson("s1", false), kp.public)
        val r = sv.verifyScan(t, "s1", priv, session = fakeSession())
        assertFalse(r.ok)
        assertEquals("unbound", r.reason)
    }

    @Test fun a_session_id_mismatch_is_rejected() {
        val r = sv.verifyScan(token(scanJson("s1", true), "CERTdead"), "s2", priv)
        assertFalse(r.ok)
        assertEquals("session id mismatch", r.reason)
        assertTrue(r.checks.any { it.name == "session id matches issued" && !it.ok })
    }

    @Test fun the_envelope_opens_before_any_content_gate_runs() {
        val r = sv.verifyScan(token(scanJson("s1", true), "CERTdead"), "s1", priv)
        assertTrue("envelope must have opened", r.checks.any { it.name == "envelope opens" && it.ok })
        assertTrue("json must have parsed", r.checks.any { it.name == "signed content is JSON" && it.ok })
    }

    @Test fun a_bootstrap_scan_with_an_unparseable_chain_is_rejected() {
        val r = sv.verifyScan(token(scanJson("s1", true), "CERTdead"), "s1", priv)
        assertFalse(r.ok)
        assertTrue("bootstrap must be reported even on failure", r.bootstrap)
        assertNull("a failed bootstrap must not hand back a key", r.attestedKey)
    }

    @Test fun a_bootstrap_scan_with_no_chain_at_all_is_rejected() {
        val r = sv.verifyScan(token(scanJson("s1", true), "SIGdead"), "s1", priv)
        assertFalse(r.ok)
        assertEquals("no chain", r.reason)
    }

    @Test fun a_steady_state_scan_without_a_bound_key_is_rejected() {
        val r = sv.verifyScan(token(scanJson("s1", false), "SIG\u001Fdead"), "s1", priv, session = null)
        assertFalse(r.ok)
        assertEquals("no bound key for session", r.reason)
    }

    @Test fun a_steady_state_scan_with_no_signature_is_rejected() {
        // No SIG line at all — an FS-less "SIGdead" is not a signature line either.
        val r = sv.verifyScan(token(scanJson("s1", false), "SIGdead"), "s1", priv, session = fakeSession())
        assertFalse(r.ok)
        assertEquals("no signature", r.reason)
    }

    @Test fun a_steady_state_scan_whose_signature_does_not_verify_is_rejected() {
        val r = sv.verifyScan(token(scanJson("s1", false), "SIG\u001Fdead"), "s1", priv, session = fakeSession())
        assertFalse(r.ok)
        assertEquals("signature does not verify", r.reason)
    }

    @Test fun signals_are_resolved_through_the_registry() {
        val json = scanJson("s1", false).replace(
            """"signals":[]""",
            """"signals":[{"id":"INTEL_0006","severity":"CRITICAL","detail":"enforce=0"}]""")
        val r = sv.verifyScan(token(json, "SIG\u001Fdead"), "s1", priv, session = fakeSession())
        assertEquals(1, r.signals.size)
        assertEquals("INTEL_0006", r.signals.first().id)
        assertEquals("selinux_permissive", r.signals.first().kind)
    }

    // --- the app-identity cross-check -------------------------------------------

    private val attested = AttestedApp(listOf("com.example.app"), listOf("aa".repeat(32)))

    // A real EC key, so steady-state tokens carry a signature that actually verifies —
    // otherwise the signature gate short-circuits and the integrity adjudication below
    // it never runs, which would make these tests assert nothing.
    private val ec = java.security.KeyPairGenerator.getInstance("EC")
        .apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()
    private val ecSpki = Hex.encode(ec.public.encoded)

    /** A steady-state token whose SIG verifies against [ecSpki]. */
    private fun signedToken(json: String): String {
        val sig = java.security.Signature.getInstance("SHA256withECDSA").run {
            initSign(ec.private); update(json.toByteArray(Charsets.UTF_8)); sign()
        }
        return token(json, "SIG\u001F" + Hex.encode(sig))
    }

    /** A carried session standing in for one a bootstrap scan produced. */
    private fun fakeSession(
        app: AttestedApp? = attested,
        assurance: Assurance = Assurance.STRONGBOX,
        bootState: String = "Verified",
        locked: Boolean = true,
    ) = ScanSession(
        attestedKey = ecSpki, attestedApp = app, assurance = assurance,
        bootState = bootState, deviceLocked = locked,
        osPatchLevel = 202607, vendorPatchLevel = 20260701, bootPatchLevel = 20260701,
    )

    @Test fun a_self_report_disagreeing_with_the_attested_identity_raises_INTEL_0046() {
        val json = scanJson("s1", false).replace("com.example.app", "com.attacker.app")
        val r = sv.verifyScan(token(json, "SIG\u001Fdead"), "s1", priv,
                              session = fakeSession())
        assertTrue("a forged self-report must be reported",
            r.signals.any { it.id == "INTEL_0046" })
    }

    @Test fun a_self_report_with_a_forged_signer_raises_INTEL_0046() {
        val json = scanJson("s1", false).replace("aa".repeat(32), "bb".repeat(32))
        val r = sv.verifyScan(token(json, "SIG\u001Fdead"), "s1", priv,
                              session = fakeSession())
        assertTrue("the signing digest is half the identity",
            r.signals.any { it.id == "INTEL_0046" })
    }

    @Test fun an_agreeing_self_report_raises_nothing() {
        val r = sv.verifyScan(token(scanJson("s1", false), "SIG\u001Fdead"), "s1", priv,
                              session = fakeSession())
        assertFalse(r.signals.any { it.id == "INTEL_0046" || it.id == "INTEL_0037" })
    }

    @Test fun an_unlicensed_but_consistent_identity_raises_INTEL_0037_not_INTEL_0046() {
        val reg = StaticLicenseRegistry(mapOf("com.someone.else" to setOf("00".repeat(32))))
        val r = ScanVerifier(licenses = reg)
            .verifyScan(token(scanJson("s1", false), "SIG\u001Fdead"), "s1", priv,
                        session = fakeSession())
        assertTrue(r.signals.any { it.id == "INTEL_0037" })
        assertFalse("a stale licence table is not a compromise",
            r.signals.any { it.id == "INTEL_0046" })
    }

    @Test fun an_absent_self_report_emits_nothing() {
        val json = scanJson("s1", false)
            .replace(""","app":{"package":"com.example.app","signer":"${"aa".repeat(32)}"}""", "")
        val r = sv.verifyScan(token(json, "SIG\u001Fdead"), "s1", priv,
                              session = fakeSession())
        assertFalse("fail open: absence is not evidence",
            r.signals.any { it.id == "INTEL_0046" || it.id == "INTEL_0037" })
    }

    @Test fun no_attested_identity_to_compare_against_emits_nothing() {
        val r = sv.verifyScan(token(scanJson("s1", false), "SIG\u001Fdead"), "s1", priv,
                              session = fakeSession(app = null))
        assertFalse("nothing to cross-check means nothing to report",
            r.signals.any { it.id == "INTEL_0046" || it.id == "INTEL_0037" })
    }

    // --- device integrity: the checks a chain-only verifier would miss -------------

    @Test fun an_unverified_boot_is_authentic_but_not_trustworthy() {
        // The TrickyStore case: a leaked keybox that DOES chain to a pinned Google root,
        // on a device whose hardware honestly reports an unlocked, unverified boot. The
        // token is genuine; the device is not. Conflating the two is how a rooted rig
        // passes as clean.
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession(bootState = "Unverified", locked = false))
        assertFalse("an unverified, unlocked boot is not device-integrity clean",
            r.deviceIntegrityOk)
        assertFalse(r.checks.first { it.name == "verified boot state = Verified" }.ok)
        assertFalse(r.checks.first { it.name == "device locked" }.ok)
    }

    @Test fun a_software_keystore_fails_the_assurance_gate() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession(assurance = Assurance.SOFTWARE))
        assertFalse("no hardware root of trust", r.deviceIntegrityOk)
        assertFalse(r.checks.first { it.name == "hardware security level >= TEE" }.ok)
    }

    @Test fun a_revoked_keybox_is_a_forgery_not_merely_an_integrity_failure() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession().copy(keyboxRevoked = true))
        assertFalse("a revoked keybox must REJECT, not merely downgrade", r.ok)
        assertFalse(r.checks.first { it.name == "no revoked keybox" }.ok)
    }

    @Test fun cross_level_keybox_reuse_rejects_and_raises_INTEL_0016() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession().copy(crossLevelReuse = true))
        assertFalse("one keybox signing both levels proves injection", r.ok)
        assertTrue(r.signals.any { it.id == "INTEL_0016" })
    }

    @Test fun a_boot_state_spoofer_rejects_and_raises_INTEL_0055() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession().copy(bootStateSpoofer = true))
        assertFalse("props claiming a boot the TEE denies is a proven forgery", r.ok)
        assertTrue(r.signals.any { it.id == "INTEL_0055" })
    }

    @Test fun a_software_attested_environment_raises_INTEL_0056() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession(assurance = Assurance.SOFTWARE).copy(softwareAttested = true))
        assertTrue(r.signals.any { it.id == "INTEL_0056" })
    }

    @Test fun a_missing_strongbox_chain_is_a_signal_not_a_gate() {
        // A genuine StrongBox device can hit a transient keygen failure, so this must
        // inform policy without failing the device outright.
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession().copy(strongboxChainMissing = true))
        assertTrue(r.signals.any { it.id == "INTEL_0045" })
        assertTrue("must not be an AUTH gate",
            r.checks.filter { it.kind == CheckKind.AUTH }.none { it.name.contains("StrongBox") && !it.ok })
    }

    @Test fun a_clean_session_passes_both_axes() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession())
        assertTrue("a genuine locked StrongBox device is integrity-clean", r.deviceIntegrityOk)
        assertTrue("a correctly signed token from a clean device passes every gate", r.ok)
    }

    // --- fingerprint + patch signals ---------------------------------------------

    private fun scanJsonWithFp(sessionId: String, fp: String) =
        """{"schemaVersion":4,"type":"scan","sessionId":"$sessionId","name":"checkout",""" +
        """"ts":1,"bootstrap":false,"app":{"package":"com.example.app","signer":"${"aa".repeat(32)}"},""" +
        """"fp":$fp,""" +
        """"device":{"api":36,"abi":"arm64-v8a","model":"X"},"signals":[]}"""

    @Test fun the_fingerprint_is_surfaced_on_the_result() {
        val fp = """{"id":"${"11".repeat(32)}","aid":"${"22".repeat(32)}","lvl":"L1",""" +
                 """"build":"google/raven/raven:16","kernel":"6.1.145","patch":"2026-07-05",""" +
                 """"installer":"com.android.vending"}"""
        val r = sv.verifyScan(signedToken(scanJsonWithFp("s1", fp)), "s1", priv,
                              session = fakeSession().copy(fingerprint = null))
        assertEquals("11".repeat(32), r.fingerprint?.id)
        assertEquals("L1", r.fingerprint?.securityLevel)
        assertEquals("com.android.vending", r.fingerprint?.installer)
    }

    @Test fun a_stale_attested_patch_raises_INTEL_0050() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession().copy(osPatchLevel = 202001,
                                         vendorPatchLevel = 20200101, bootPatchLevel = 20200101))
        assertTrue(r.signals.any { it.id == "INTEL_0050" })
    }

    @Test fun a_current_attested_patch_raises_nothing() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession())
        assertFalse(r.signals.any { it.id == "INTEL_0050" })
    }

    @Test fun staleness_uses_the_OLDEST_of_the_three_patch_levels() {
        val r = sv.verifyScan(signedToken(scanJson("s1", false)), "s1", priv,
            session = fakeSession().copy(osPatchLevel = 202607, bootPatchLevel = 20200101))
        assertTrue("an ancient bootloader must not hide behind a current framework patch",
            r.signals.any { it.id == "INTEL_0050" })
    }

    @Test fun a_self_report_disagreeing_with_the_attested_patch_raises_INTEL_0019() {
        val fp = """{"id":"","aid":"","lvl":"","build":"","kernel":"","patch":"2026-08-05","installer":""}"""
        val r = sv.verifyScan(signedToken(scanJsonWithFp("s1", fp)), "s1", priv,
            session = fakeSession().copy(osPatchLevel = 202604, fingerprint = null))
        assertTrue(r.signals.any { it.id == "INTEL_0019" })
    }

    @Test fun day_precision_does_not_false_positive_against_a_month_precision_attestation() {
        // THE trap: 202604 vs "2026-04-05" must compare equal at month precision.
        val fp = """{"id":"","aid":"","lvl":"","build":"","kernel":"","patch":"2026-04-05","installer":""}"""
        val r = sv.verifyScan(signedToken(scanJsonWithFp("s1", fp)), "s1", priv,
            session = fakeSession().copy(osPatchLevel = 202604, fingerprint = null))
        assertFalse("same month must NOT mismatch", r.signals.any { it.id == "INTEL_0019" })
    }

    @Test fun a_missing_patch_on_either_side_emits_nothing() {
        val none = """{"id":"","aid":"","lvl":"","build":"","kernel":"","patch":"","installer":""}"""
        val r = sv.verifyScan(signedToken(scanJsonWithFp("s1", none)), "s1", priv,
            session = fakeSession().copy(osPatchLevel = 202604, fingerprint = null))
        assertFalse("fail open on a missing self-report", r.signals.any { it.id == "INTEL_0019" })

        val some = """{"id":"","aid":"","lvl":"","build":"","kernel":"","patch":"2026-04-05","installer":""}"""
        val r2 = sv.verifyScan(signedToken(scanJsonWithFp("s1", some)), "s1", priv,
            session = fakeSession().copy(osPatchLevel = null, fingerprint = null))
        assertFalse("fail open on a missing attested value", r2.signals.any { it.id == "INTEL_0019" })
    }
}
