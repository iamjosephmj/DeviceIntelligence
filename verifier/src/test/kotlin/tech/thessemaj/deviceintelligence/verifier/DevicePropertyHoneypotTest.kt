package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Device-property honeypot — the backend port of the native `device_property_binding`.
 * A key generated with device-properties attestation carries the TEE's own device
 * identity in the leaf; a spoofer that fakes `Build.*` to a different model gets
 * caught by the mismatch. Uses a REAL enroll bundle captured from a TrickyStore rig
 * (attests `Pixel 6 Pro / deviceintelligence`, self-reports `Pixel 6 / oriole`), plus the older
 * pre-honeypot fixture to prove fail-open.
 */
class DevicePropertyHoneypotTest {

    private fun res(p: String) = javaClass.getResourceAsStream(p)!!.bufferedReader().use { it.readText() }.trim()
    private val ev = EnrollVerifier(SessionSigner(LabKeys.SERVER_KEY))

    @Test fun spoofed_build_props_carried_to_session() {
        val signer = SessionSigner(LabKeys.SERVER_KEY, maxAgeSeconds = Long.MAX_VALUE)
        val enroll = EnrollVerifier(signer).enroll(res("/pixel-enroll-spoofed.bundle"), res("/pixel-enroll-spoofed-challenge.hex"))
        // enroll issues a session (TEE call made) and CARRIES the mismatch; challenge REJECTs.
        assertTrue("enroll issues a session; verdict deferred to challenge", enroll.ok)
        val check = enroll.checks.first { it.name == "device-property attestation matches self-report" }
        assertFalse(check.ok)
        assertTrue("names the mismatching field", check.detail.contains("attested"))
        val session = signer.open(enroll.sessionId!!)!!
        assertTrue("device-property mismatch carried to the session", session.devicePropMismatch)
    }

    @Test fun attested_properties_are_extracted() {
        // The captured leaf really carries attestationId* tags (proves the parse).
        val text = Keystream.decryptHex(res("/pixel-enroll-spoofed.bundle"))
        val binding = text.substring(text.indexOf(TokenDecoder.BINDING_SEP) + TokenDecoder.BINDING_SEP.length)
        val certs = binding.split("\n").filter { it.startsWith("CERT") }.map { it.substring(5) }
        val leaf = ChainVerifier(PinnedRoots.default).parseChain(certs).first()
        val props = Attestation.deviceProperties(leaf)
        assertTrue("device-properties present in the leaf", props.isNotEmpty())
        assertTrue("model attested", props["model"]?.isNotBlank() == true)
    }

    @Test fun legacy_bundle_fails_open() {
        // The older fixture predates device-properties attestation: no attestationId,
        // so the honeypot must NOT fire (fail-open), and enrollment still succeeds.
        val enroll = ev.enroll(res("/pixel-enroll.bundle"), res("/pixel-enroll-challenge.hex"))
        val check = enroll.checks.first { it.name == "device-property attestation matches self-report" }
        assertTrue("absent attested props -> fail-open (no mismatch)", check.ok)
    }
}
