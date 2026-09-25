package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test
import java.security.cert.X509Certificate

class EnrollVerifierTest {
    private val ev = EnrollVerifier(SessionSigner("k".toByteArray()))

    private fun tokenOf(plain: String) = Hex.encode(Keystream.decrypt(plain.toByteArray()))

    @Test fun unbound_bundle_rejected() {
        val signed = """{"schemaVersion":3,"type":"enroll","ts":1,"enrollChallenge":"ab",""" +
            """"device":{"api":36,"abi":"arm64-v8a","model":"X"},"attestedKey":"00"}"""
        val r = ev.enroll(tokenOf(signed), issuedEnrollChallenge = "ab")  // no --BINDING
        assertFalse(r.ok); assertNull(r.sessionId)
    }

    @Test fun wrong_enroll_challenge_rejected() {
        val signed = """{"schemaVersion":3,"type":"enroll","ts":1,"enrollChallenge":"ab",""" +
            """"device":{"api":36,"abi":"arm64-v8a","model":"X"},"attestedKey":"00"}""" +
            "\n--BINDING\nCERTdead"
        val r = ev.enroll(tokenOf(signed), issuedEnrollChallenge = "ZZ")
        assertFalse(r.ok)
        assertTrue(r.checks.first { it.name == "enroll challenge matches issued" }.ok.not())
    }

    @Test fun pixel_trickystore_bundle_enrolls_and_carries_findings() {
        // The captured Pixel bundle is a TrickyStore rig (KernelSU-Next + Integrity-Box): the
        // leaked keybox chains to a pinned Google root, but its hardware attestation honestly
        // reports an Unverified/unlocked boot. enroll() ISSUES a session (the TEE call was
        // made) and CARRIES the findings; the verdict is deferred to challenge().
        val signer = SessionSigner(LabKeys.SERVER_KEY, maxAgeSeconds = Long.MAX_VALUE)
        val r = EnrollVerifier(signer).enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))
        assertTrue("leaked keybox chain still reaches a pinned Google root",
            r.checks.first { it.name == "chain -> pinned Google root" }.ok)
        assertTrue("enroll issues a session; verdict deferred to challenge", r.ok)
        assertNotNull(r.sessionId)
        val session = signer.open(r.sessionId!!)!!
        assertTrue("chain trusted carried", session.chainTrusted)
        assertNotEquals("hardware attestation reports the honest (non-Verified) boot",
            "Verified", session.bootState)
    }
    // The gradeStrongBox truth-table tests lived here. Removed with INTEL_0039 and its
    // strongbox-devices.json capability list — see the registry tombstone.

    // --- F2 (2026-09-10 spec): attested signer pin — the third enroll hard-fail ---

    @Test fun signer_pin_matching_attested_app_enrolls() {
        // The real Pixel chain carries a genuine OS/TEE-computed signature digest;
        // pinning exactly it must not disturb the enrollment.
        val pin = Attestation.attestedApp(leafCert(res("/pixel-enroll.bundle")))!!.signatureDigests.first()
        val r = EnrollVerifier(SessionSigner("k".toByteArray()), expectedSignerSha256 = pin)
            .enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))
        assertTrue(r.ok)
    }

    @Test fun signer_pin_mismatch_hard_fails_enrollment() {
        val r = EnrollVerifier(SessionSigner("k".toByteArray()), expectedSignerSha256 = "00".repeat(32))
            .enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))
        assertFalse(r.ok)
        assertEquals("signer pin", r.reason)
        assertTrue(r.checks.any { !it.ok && it.name.contains("signer pin") })
    }

    @Test fun null_pin_records_dev_unpinned_and_continues() {
        val r = EnrollVerifier(SessionSigner("k".toByteArray()))
            .enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))
        assertTrue(r.ok)
        assertTrue(r.checks.any { it.name == "signer pin configured" })
    }

    /** The leaf of the bundle's CERT lines, parsed exactly as EnrollVerifier does. */
    private fun leafCert(bundleHex: String): X509Certificate {
        val text = Keystream.decryptHex(bundleHex)
        val binding = text.substring(text.indexOf(TokenDecoder.BINDING_SEP) + TokenDecoder.BINDING_SEP.length)
        return ChainVerifier(PinnedRoots.default)
            .parseChain(binding.split("\n").filter { it.startsWith("CERT") }.map { it.substring(5) })
            .first()
    }

    private fun res(p: String) = EnrollVerifierTest::class.java.getResourceAsStream(p)!!
        .bufferedReader().use { it.readText() }.trim()
}
