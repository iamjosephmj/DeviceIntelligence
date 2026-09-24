package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Tests the Android Key Attestation extension reader against a REAL StrongBox leaf
 * (from the pixel-enroll fixture) and a root cert that has no attestation extension.
 */
class AttestationTest {
    private fun cert(p: String): X509Certificate =
        javaClass.getResourceAsStream(p)!!.use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
        }

    @Test fun reads_security_level_and_challenge_from_real_leaf() {
        val leaf = cert("/attest-leaf.der")
        val f = Attestation.fields(leaf)
        assertEquals("StrongBox leaf -> securityLevel 2", 2, f.securityLevel)   // parity with native kd.sl
        assertEquals("StrongBox", f.securityLevelName)
        // boot state resolves to a known enum (0..3) or null; the name must be defined.
        assertNotNull(f.bootStateName)
        // attestationChallenge (element 4) is the 32-byte server nonce.
        assertEquals(32, Attestation.challenge(leaf).size)
    }

    @Test fun device_properties_map_is_ascii_and_never_throws() {
        val leaf = cert("/attest-leaf.der")
        val props = Attestation.deviceProperties(leaf)   // may be empty; must not throw
        for ((_, v) in props) assertTrue(v.all { it.code in 0..127 })
    }

    @Test fun throws_on_cert_without_attestation_extension() {
        val root = cert("/attest-root.der")               // Google root: no KeyDescription
        assertThrows(IllegalArgumentException::class.java) { Attestation.challenge(root) }
        assertThrows(IllegalArgumentException::class.java) { Attestation.fields(root) }
    }

    @Test fun attested_app_is_read_from_the_real_leaf() {
        val app = Attestation.attestedApp(cert("/attest-leaf.der"))
        assertNotNull("the StrongBox fixture leaf must carry tag 709", app)
        assertTrue("package name must be present", app!!.packageNames.isNotEmpty())
        assertTrue("package looks like an applicationId", app.packageNames.first().contains('.'))
        assertTrue("at least one signing digest", app.signatureDigests.isNotEmpty())
        assertEquals("digests are SHA-256 hex", 64, app.signatureDigests.first().length)
        assertTrue("digests are lowercase hex",
            app.signatureDigests.all { it.matches(Regex("[0-9a-f]{64}")) })
    }

    @Test fun a_cert_without_tag_709_returns_null() {
        assertNull(Attestation.attestedApp(cert("/attest-root.der")))
    }

    @Test fun attested_platform_is_read_from_the_real_leaf() {
        val p = Attestation.attestedPlatform(cert("/attest-leaf.der"))
        assertNotNull("osVersion must parse", p.osVersion)
        assertNotNull("osPatchLevel must parse", p.osPatchLevel)
        // osPatchLevel is YYYYMM — six digits, a plausible year, a real month.
        val opl = p.osPatchLevel!!
        assertTrue("osPatchLevel looks like YYYYMM: $opl", opl in 200000..299912)
        assertTrue("month is 1..12: $opl", opl % 100 in 1..12)
    }

    @Test fun attested_platform_on_a_cert_without_the_extension_is_all_null() {
        val p = Attestation.attestedPlatform(PinnedRoots.default.first())
        assertNull(p.osVersion); assertNull(p.osPatchLevel)
        assertNull(p.vendorPatchLevel); assertNull(p.bootPatchLevel)
    }
}
