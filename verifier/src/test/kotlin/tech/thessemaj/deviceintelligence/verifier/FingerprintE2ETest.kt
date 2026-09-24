package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * End-to-end: a REAL bootstrap scan captured from a Pixel 6 Pro (Android 16),
 * verified by the real ScanVerifier with the sample's private key.
 *
 * This is the check that the device and the backend agree on the fingerprint wire
 * format. It runs without a device, so CI keeps it honest.
 */
class FingerprintE2ETest {
    private fun res(p: String) = javaClass.getResourceAsStream(p)!!.bufferedReader().readText().trim()

    private fun priv() = KeyFactory.getInstance("XDH").generatePrivate(
        PKCS8EncodedKeySpec(Base64.getDecoder().decode(
            res("/fp-e2e-priv.pem")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace(Regex("\\s"), ""))))

    @Test fun a_real_bootstrap_scan_carries_a_well_formed_fingerprint() {
        val r = ScanVerifier().verifyScan(res("/fp-e2e.token"), res("/fp-e2e-session.txt"), priv())

        assertTrue("envelope must open", r.checks.first { it.name == "envelope opens" }.ok)
        assertTrue("must be the bootstrap scan", r.bootstrap)

        val fp = assertNotNull("a real scan must carry a fingerprint", r.fingerprint).let { r.fingerprint!! }
        assertTrue("id is a lowercase sha256 digest", fp.id!!.matches(Regex("[0-9a-f]{64}")))
        assertTrue("aid is a lowercase sha256 digest", fp.aid!!.matches(Regex("[0-9a-f]{64}")))
        assertEquals("a real Widevine level", "L1", fp.securityLevel)
        assertTrue("kernel is readable natively", fp.kernel!!.matches(Regex("\\d+\\.\\d+.*")))
        assertTrue("build fingerprint is readable natively", fp.build!!.contains("/"))
        assertTrue("security patch is readable natively", fp.patch!!.matches(Regex("\\d{4}-\\d{2}-\\d{2}")))
    }

    @Test fun the_raw_identifiers_never_appear_in_the_token() {
        // Measured on the reference device during the design spike. If either ever
        // shows up in a payload, the on-device peppering has been bypassed.
        val token = res("/fp-e2e.token")
        assertFalse("raw Widevine id must never reach the wire",
            token.contains("801bd47e05bbcf5a554e3ef7d808b104401951f8a2f4436013b756eb2bbcd431"))
        assertFalse("raw ANDROID_ID must never reach the wire", token.contains("ff140610a329fbf5"))
    }
}
