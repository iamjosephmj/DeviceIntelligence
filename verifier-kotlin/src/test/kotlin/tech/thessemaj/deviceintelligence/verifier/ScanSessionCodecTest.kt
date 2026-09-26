package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanSessionCodecTest {
    private val session = ScanSession(
        attestedKey = "3059301306072a8648ce3d020106082a8648ce3d030107",
        attestedApp = AttestedApp(
            packageNames = listOf("tech.thessemaj.deviceintelligence.sample"),
            signatureDigests = listOf("aa".repeat(32)),
        ),
        assurance = Assurance.STRONGBOX,
        bootState = "Verified",
        deviceLocked = true,
        osPatchLevel = 202604,
        vendorPatchLevel = 20260405,
        bootPatchLevel = 20260405,
        fingerprint = DeviceFingerprint(
            id = "id", aid = "aid", securityLevel = "L1",
            build = "google/panther/panther:16", kernel = "6.1.145",
            patch = "2026-04-05", installer = "com.android.vending",
        ),
    )

    @Test fun `roundtrip preserves every fact`() {
        val decoded = ScanSessionCodec.decode(ScanSessionCodec.encode(session))
        assertEquals(session, decoded)
    }

    @Test fun `fingerprint fields survive the roundtrip`() {
        val decoded = ScanSessionCodec.decode(ScanSessionCodec.encode(session))
        assertEquals("google/panther/panther:16", decoded.fingerprint!!.build)
        assertEquals("com.android.vending", decoded.fingerprint!!.installer)
        assertEquals("L1", decoded.fingerprint!!.securityLevel)
    }

    @Test fun `a truncated document grades down to suspicious, never clean`() {
        val decoded = ScanSessionCodec.decode("""{"attestedKey":"ab"}""")
        assertEquals(Assurance.SOFTWARE, decoded.assurance)
        assertEquals("?", decoded.bootState)
        assertFalse(decoded.chainTrusted)
        assertTrue(decoded.keyboxRevoked)
        assertTrue(decoded.bootStateSpoofer)
        assertTrue(decoded.softwareAttested)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a session without attestedKey is rejected`() {
        ScanSessionCodec.decode("""{"bootState":"Verified"}""")
    }
}
