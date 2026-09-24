package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

class E2EFixtureTest {
    private fun res(p: String) = javaClass.getResourceAsStream(p)!!.bufferedReader().use { it.readText() }.trim()

    /**
     * Captured Pixel bundle = a TrickyStore/keybox-injection spoof (KernelSU-Next +
     * Integrity-Box). Under the attest-once/challenge-per-request design, initialize()/enroll
     * must SUCCEED whenever the TEE produced a fresh, Google-rooted attestation — it does not
     * reject on integrity findings. Instead every finding is carried (HMAC-signed) in the
     * session and adjudicated at challenge(). Here we prove enroll issues a session and the
     * forgery is carried; the challenge REJECT/COMPROMISED decision itself is covered with
     * synthetic sessions in ChallengeVerifyTest.
     */
    @Test fun pixel_trickystore_bundle_enrolls_and_carries_findings() {
        val signer = SessionSigner(LabKeys.SERVER_KEY, maxAgeSeconds = Long.MAX_VALUE)
        val enroll = EnrollVerifier(signer).enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))

        assertTrue("enroll issues a session (TEE call was made)", enroll.ok)
        assertNotNull(enroll.sessionId)

        val session = signer.open(enroll.sessionId!!)!!
        assertTrue("leaked keybox still chains to a pinned Google root", session.chainTrusted)
        // (The retired leaf-notBefore heuristic no longer runs; this honestly-unlocked
        // Pixel is caught at challenge as COMPROMISED via its device-integrity facts below.)
        // The real hardware attestation reports the truth for this rooted/unlocked Pixel.
        assertNotEquals("Verified", session.bootState)
    }
}
