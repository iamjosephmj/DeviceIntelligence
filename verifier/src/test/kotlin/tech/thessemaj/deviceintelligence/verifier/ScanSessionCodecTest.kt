package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/**
 * The stateless design makes every caller store a [ScanSession] between the
 * bootstrap scan and every later one, so the codec is part of the contract rather
 * than CLI plumbing. A field that fails to round-trip is a fact silently dropped
 * from every steady-state verdict — which is why this test asserts the WHOLE
 * object, not a sample of it.
 */
class ScanSessionCodecTest {

    private val full = ScanSession(
        attestedKey = "3059301306072a8648ce3d020106082a8648ce3d03010703420004aabb",
        attestedApp = AttestedApp(
            packageNames = listOf("com.example.app", "com.example.other"),
            signatureDigests = listOf("aa".repeat(32), "bb".repeat(32)),
        ),
        assurance = Assurance.STRONGBOX,
        bootState = "Verified",
        deviceLocked = true,
        chainTrusted = true,
        keyboxRevoked = false,
        crossLevelReuse = false,
        devicePropMismatch = false,
        bootStateSpoofer = false,
        strongboxChainMissing = false,
        softwareAttested = false,
        osPatchLevel = 202604,
        vendorPatchLevel = 20260405,
        bootPatchLevel = 20260405,
        fingerprint = DeviceFingerprint(
            id = "cc".repeat(32),
            aid = "dd".repeat(32),
            securityLevel = "L1",
            build = "google/raven/raven:16/BP41.250:user/release-keys",
            kernel = "6.1.145-android14-11",
            patch = "2026-04-05",
            installer = "com.android.vending",
        ),
    )

    @Test fun a_full_session_round_trips_field_for_field() {
        assertEquals(full, ScanSessionCodec.decode(ScanSessionCodec.encode(full)))
    }

    @Test fun the_compromised_flags_round_trip() {
        // Every one of these defaults to the benign value, so a codec that dropped
        // them would silently turn a compromised device into a clean one.
        val bad = full.copy(
            assurance = Assurance.SOFTWARE,
            bootState = "Unverified",
            deviceLocked = false,
            chainTrusted = false,
            keyboxRevoked = true,
            crossLevelReuse = true,
            devicePropMismatch = true,
            bootStateSpoofer = true,
            strongboxChainMissing = true,
            softwareAttested = true,
        )
        assertEquals(bad, ScanSessionCodec.decode(ScanSessionCodec.encode(bad)))
    }

    @Test fun the_nullable_fields_round_trip_as_null() {
        val sparse = full.copy(
            attestedApp = null,
            osPatchLevel = null,
            vendorPatchLevel = null,
            bootPatchLevel = null,
            fingerprint = null,
        )
        assertEquals(sparse, ScanSessionCodec.decode(ScanSessionCodec.encode(sparse)))
    }

    @Test fun strings_needing_escapes_survive() {
        val odd = full.copy(
            fingerprint = full.fingerprint!!.copy(build = """a"quote\and/slash""" + ""),
        )
        assertEquals(odd, ScanSessionCodec.decode(ScanSessionCodec.encode(odd)))
    }

    /**
     * The other half of the contract: a session established by the PYTHON reference
     * backend must adjudicate identically here. The fixture is real output from
     * `verify_token.py --scan` over the fp-e2e capture, so a field either side
     * renames or drops fails this test instead of silently changing a verdict.
     */
    @Test fun a_session_from_the_python_backend_decodes() {
        val json = javaClass.getResourceAsStream("/py-session.json")!!.bufferedReader().readText()
        val s = ScanSessionCodec.decode(json)

        assertEquals(Assurance.STRONGBOX, s.assurance)
        assertEquals("SelfSigned", s.bootState)
        assertTrue("the boot-state spoofer must survive the crossing", s.bootStateSpoofer)
        assertTrue(s.deviceLocked)
        assertTrue(s.chainTrusted)
        assertFalse(s.keyboxRevoked)
        assertFalse(s.crossLevelReuse)
        assertFalse(s.devicePropMismatch)
        assertFalse(s.softwareAttested)
        assertEquals(202604, s.osPatchLevel)
        assertEquals(20260405, s.vendorPatchLevel)
        assertEquals(20260405, s.bootPatchLevel)
        assertEquals(listOf("tech.thessemaj.deviceintelligence.sample"), s.attestedApp?.packageNames)
        assertEquals(listOf("a91535782adbd690b915679d456628153166d35527ea867ab830bccd730065a4"),
            s.attestedApp?.signatureDigests)
        assertEquals("L1", s.fingerprint?.securityLevel)
        assertTrue(s.fingerprint!!.build!!.startsWith("google/raven/raven:16"))
        assertNull("an unreadable field crosses as null, not as an empty string",
            s.fingerprint!!.installer)
        // Re-encoding it here must produce something this codec reads back identically.
        assertEquals(s, ScanSessionCodec.decode(ScanSessionCodec.encode(s)))
    }

    @Test fun a_malformed_document_is_rejected_rather_than_half_decoded() {
        assertThrows(IllegalArgumentException::class.java) {
            ScanSessionCodec.decode("""{"assurance":"TEE"}""")   // no attestedKey
        }
    }
}
