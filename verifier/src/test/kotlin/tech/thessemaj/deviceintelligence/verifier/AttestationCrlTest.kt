package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Keybox-revocation (CRL) enrollment gate — the backend port of the native
 * `attest_crl`. Uses the real Pixel enroll fixture: the chain passes with the
 * default (empty) CRL, and fails closed once its own leaf serial is revoked.
 */
class AttestationCrlTest {

    private fun res(p: String) = javaClass.getResourceAsStream(p)!!.bufferedReader().use { it.readText() }.trim()

    /** Pull the CERT chain out of the encrypted enroll bundle the way EnrollVerifier does. */
    private fun fixtureChain(): List<java.security.cert.X509Certificate> {
        val text = Keystream.decryptHex(res("/pixel-enroll.bundle"))
        val binding = text.substring(text.indexOf(TokenDecoder.BINDING_SEP) + TokenDecoder.BINDING_SEP.length)
        val certs = binding.split("\n").filter { it.startsWith("CERT") }.map { it.substring(5) }
        return ChainVerifier(PinnedRoots.default).parseChain(certs)
    }

    @Test fun parse_ignores_comments_and_normalizes() {
        val crl = AttestationCrl.parse(
            """
            # a comment
            0x00A1B2   # leading zeros + 0x prefix

            deadBEEF
            """.trimIndent(),
        )
        assertEquals(2, crl.size)
        // "00A1B2" -> "a1b2"; a chain-cert serial of 0xA1B2 must match.
        val serials = setOf("a1b2", "deadbeef")
        assertTrue(serials.all { AttestationCrl.parse(it).size == 1 })
    }

    @Test fun clean_chain_passes_with_empty_crl() {
        // The bundled default CRL is empty, so the real fixture enrolls fine.
        val enroll = EnrollVerifier(SessionSigner(LabKeys.SERVER_KEY))
            .enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))
        val crlCheck = enroll.checks.firstOrNull { it.name == "no revoked keybox in chain" }
        assertNotNull("the CRL check should run", crlCheck)
        assertTrue("clean chain must pass the CRL gate", crlCheck!!.ok)
    }

    @Test fun revoked_serial_carried_to_session() {
        val leafSerial = fixtureChain().first().serialNumber.toString(16)
        val revokingCrl = AttestationCrl.parse(leafSerial)   // revoke the fixture's own leaf
        assertNull(revokingCrl.firstRevoked(emptyList()))    // sanity: empty chain, nothing revoked

        val signer = SessionSigner(LabKeys.SERVER_KEY, maxAgeSeconds = Long.MAX_VALUE)
        val enroll = EnrollVerifier(signer, crl = revokingCrl)
            .enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))

        // enroll issues a session (TEE call made) and CARRIES the revocation; challenge REJECTs.
        assertTrue("enroll issues a session; verdict deferred to challenge", enroll.ok)
        val crlCheck = enroll.checks.first { it.name == "no revoked keybox in chain" }
        assertFalse(crlCheck.ok)
        assertTrue("the finding names the revoked serial", crlCheck.detail.contains("revoked serial"))
        val session = signer.open(enroll.sessionId!!)!!
        assertTrue("revocation carried to the session", session.keyboxRevoked)
    }
}
