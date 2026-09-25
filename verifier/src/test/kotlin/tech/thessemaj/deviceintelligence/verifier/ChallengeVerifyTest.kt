package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class ChallengeVerifyTest {
    private val NOW = 1_800_000_000L
    private val signer = SessionSigner("k".toByteArray(), now = { NOW })

    private fun makeToken(kp: java.security.KeyPair, sessionId: String, challenge: String,
                          signals: String = ""): String {
        val signed = """{"schemaVersion":3,"type":"challenge","sessionId":"$sessionId",""" +
            """"name":"login","ts":1,"challenge":"$challenge","signals":[$signals]}"""
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(kp.private); update(signed.toByteArray()); sign()
        }
        val plain = signed + "\n--BINDING\nSIG" + Hex.encode(sig)
        return Hex.encode(Keystream.decrypt(plain.toByteArray()))   // XOR is its own inverse
    }

    @Test fun trustworthy_clean() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val spki = Hex.encode(kp.public.encoded)
        val sid = signer.issue(Session(spki, Assurance.STRONGBOX, "Verified", true, NOW))
        val token = makeToken(kp, sid, "abcd")
        val r = TokenVerifier().verifyChallenge(token, issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.TRUSTWORTHY, r.decision)
        assertTrue(r.authentic)
    }

    @Test fun replay_wrong_challenge_rejected() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.STRONGBOX, "Verified", true, NOW))
        val token = makeToken(kp, sid, "abcd")
        val r = TokenVerifier().verifyChallenge(token, issuedChallenge = "9999", sessionSigner = signer)
        assertEquals(Decision.REJECT, r.decision)
    }

    @Test fun forged_signature_rejected() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        // session pins `kp`, but token signed by `other`
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.STRONGBOX, "Verified", true, NOW))
        val token = makeToken(other, sid, "abcd")
        val r = TokenVerifier().verifyChallenge(token, issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.REJECT, r.decision)
    }

    // ---- carried attestation forgeries -> REJECT at challenge (enroll no longer blocks) ----
    private fun rejectsWithSessionFlag(session: (String) -> Session) {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val sid = signer.issue(session(Hex.encode(kp.public.encoded)))
        val token = makeToken(kp, sid, "abcd")
        val r = TokenVerifier().verifyChallenge(token, issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.REJECT, r.decision)
        assertFalse("a carried forgery is an authenticity failure", r.authentic)
    }

    @Test fun boot_state_spoofer_rejected() =
        rejectsWithSessionFlag { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, bootStateSpoofer = true) }

    @Test fun untrusted_chain_rejected() =
        rejectsWithSessionFlag { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, chainTrusted = false) }

    @Test fun revoked_keybox_rejected() =
        rejectsWithSessionFlag { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, keyboxRevoked = true) }

    @Test fun cross_level_reuse_rejected() =
        rejectsWithSessionFlag { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, crossLevelReuse = true) }

    // strongboxChainMissing is now OBSERVE-ONLY (transient StrongBox failures on genuine
    // devices would otherwise false-REJECT). It surfaces as INTEL_0045 (VERY_LOW, non-blocking).
    @Test fun strongbox_chain_missing_is_observe_only() {
        val kp = kp()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.STRONGBOX, "Verified", true, NOW,
            chainTrusted = true, strongboxChainMissing = true))
        val r = TokenVerifier().verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
        assertNotEquals("observe-only: must not hard-REJECT", Decision.REJECT, r.decision)
        assertEquals(Decision.TRUSTWORTHY, r.decision)
        assertFalse("INTEL_0045 is non-blocking by default", r.signals.first { it.id == "INTEL_0045" }.blocking)
    }

    // But an integrator CAN make it hard via policy (block INTEL_0045).
    @Test fun strongbox_chain_missing_blockable_by_policy() {
        val kp = kp()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.STRONGBOX, "Verified", true, NOW,
            chainTrusted = true, strongboxChainMissing = true))
        val r = TokenVerifier(policy = Policy(block = setOf("INTEL_0045")))
            .verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.COMPROMISED, r.decision)
    }

    // The carried forgeries also surface as first-class registry SIGs in the verdict.
    private fun signalsFor(session: (String) -> Session): List<ResolvedSignal> {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val sid = signer.issue(session(Hex.encode(kp.public.encoded)))
        val token = makeToken(kp, sid, "abcd")
        return TokenVerifier().verifyChallenge(token, issuedChallenge = "abcd", sessionSigner = signer).signals
    }

    @Test fun boot_state_spoof_surfaces_sig_0030() {
        val sig = signalsFor { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, bootStateSpoofer = true) }
            .first { it.id == "INTEL_0055" }
        assertEquals("attestation", sig.detector)
        assertEquals("verified_boot_prop_spoof", sig.kind)
        assertTrue(sig.blocking)
    }

    @Test fun cross_level_reuse_surfaces_sig_0032() {
        val sig = signalsFor { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, crossLevelReuse = true) }
            .first { it.id == "INTEL_0016" }
        assertEquals("keybox_cross_level_reuse", sig.kind)
        assertTrue("CRITICAL cross-level reuse blocks", sig.blocking)
    }

    @Test fun strongbox_chain_missing_surfaces_sig_0033() {
        val sig = signalsFor { Session(it, Assurance.STRONGBOX, "Verified", true, NOW, strongboxChainMissing = true) }
            .first { it.id == "INTEL_0045" }
        assertEquals("strongbox_chain_unavailable", sig.kind)
        assertEquals("VERY_LOW", sig.severity)
    }

    @Test fun clean_session_emits_no_attestation_sig() {
        val ids = signalsFor { Session(it, Assurance.STRONGBOX, "Verified", true, NOW) }.map { it.id }
        assertFalse(ids.contains("INTEL_0055"))
        assertFalse(ids.contains("INTEL_0016")); assertFalse(ids.contains("INTEL_0045"))
    }

    private fun kp() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /** A GENUINE TEE-only device (no StrongBox, not a downgrade) must stay TRUSTWORTHY — no false positive. */
    @Test fun genuine_tee_only_device_is_trustworthy() {
        val kp = kp()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.TEE, "Verified", true, NOW,
            chainTrusted = true))
        val r = TokenVerifier().verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.TRUSTWORTHY, r.decision)
    }

    /**
     * INTEL_0056: an explicitly software-attested environment (emulator / no hardware keystore).
     * This is the robust, generic emulator signal — it is derived from the SIGNED attestation,
     * so no anti-emulation layer that neutralises properties, sensors or telephony can hide it.
     */
    @Test fun software_attested_environment_surfaces_sig_0044() {
        val kp = kp()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.SOFTWARE, "Verified", true, NOW,
            chainTrusted = true, softwareAttested = true))
        val r = TokenVerifier().verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
        val sig = r.signals.first { it.id == "INTEL_0056" }
        assertEquals("software_attested_environment", sig.kind)
        assertTrue("INTEL_0056 blocks under default policy", sig.blocking)
        assertNotEquals(Decision.TRUSTWORTHY, r.decision)
    }

    /**
     * PRECISION: a missing/unparseable securityLevel grades to Assurance.SOFTWARE so the
     * hardware gate fails safe — but it must NOT raise INTEL_0056, which asserts a software
     * keystore was actually proven. Absence of evidence is not evidence of an emulator.
     */
    @Test fun unparseable_security_level_fails_gate_but_claims_nothing() {
        val kp = kp()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.SOFTWARE, "Verified", true, NOW,
            chainTrusted = true, softwareAttested = false))
        val r = TokenVerifier().verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
        assertFalse("hardware gate still fails safe", r.deviceIntegrityOk)
        assertTrue("but no software-attestation claim is made", r.signals.none { it.id == "INTEL_0056" })
    }

    /** Real hardware never raises the software-environment signal. */
    @Test fun hardware_attested_device_raises_no_sig_0044() {
        val kp = kp()
        for (a in listOf(Assurance.TEE, Assurance.STRONGBOX)) {
            val sid = signer.issue(Session(Hex.encode(kp.public.encoded), a, "Verified", true, NOW, chainTrusted = true))
            val r = TokenVerifier().verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
            assertTrue("no INTEL_0056 for $a", r.signals.none { it.id == "INTEL_0056" })
        }
    }

    /** Policy tier: requireStrongBox rejects any TEE-only attestation outright. */
    @Test fun require_strongbox_policy_rejects_tee_only() {
        val kp = kp()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.TEE, "Verified", true, NOW,
            chainTrusted = true))
        val r = TokenVerifier(policy = Policy(requireStrongBox = true))
            .verifyChallenge(makeToken(kp, sid, "abcd"), issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.COMPROMISED, r.decision)
        assertFalse(r.deviceIntegrityOk)
    }

    @Test fun compromised_when_signal_blocks() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.STRONGBOX, "Verified", true, NOW))
        val token = makeToken(kp, sid, "abcd", signals = """{"id":"INTEL_0006","severity":"CRITICAL","detail":"enforce=0"}""")
        val r = TokenVerifier().verifyChallenge(token, issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.COMPROMISED, r.decision)
    }

    /**
     * A perfectly-signed, correct-challenge token whose SESSION is older than the max age
     * must REJECT (spec: "forged/expired -> REJECT"). Before the SessionSigner expiry
     * check this returned TRUSTWORTHY — an immortal, relayable sessionId.
     */
    @Test fun expired_session_rejected() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val staleAt = NOW - SessionSigner.DEFAULT_MAX_AGE_SECONDS - 1
        val sid = signer.issue(Session(Hex.encode(kp.public.encoded), Assurance.STRONGBOX, "Verified", true, staleAt))
        val token = makeToken(kp, sid, "abcd")
        val r = TokenVerifier().verifyChallenge(token, issuedChallenge = "abcd", sessionSigner = signer)
        assertEquals(Decision.REJECT, r.decision)
        assertFalse(r.authentic)
    }
}
