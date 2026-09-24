package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test
import java.security.cert.CertificateFactory

/**
 * Pins the real behaviour of a captured API 28 (attestation version 2) leaf — the minSdk
 * platform. Issue #11 suspected schema drift in the RootOfTrust parse; the captured bundle
 * shows otherwise. This emulator attests at SOFTWARE level, and a software-attested
 * KeyDescription carries NO RootOfTrust at all (it lives only in teeEnforced on a device
 * with a TEE), so verifiedBootState / deviceLocked are legitimately absent. `Attestation`
 * parses what IS present (securityLevel) and returns null for what is not — the correct
 * outcome, not a parse failure.
 */
class Api28AttestationTest {
    private fun leaf() = CertificateFactory.getInstance("X.509")
        .generateCertificate(
            Api28AttestationTest::class.java.getResourceAsStream("/api28-leaf.der")
        ) as java.security.cert.X509Certificate

    @Test fun api28_software_attestation_parses_level_and_omits_bootstate() {
        val f = Attestation.fields(leaf())
        // securityLevel IS parsed on API 28 — the attestation version does not move it.
        assertEquals("software security level", 0, f.securityLevel)
        // RootOfTrust is genuinely absent under software attestation -> null, not "?".
        assertNull("no verified boot state under software attestation", f.verifiedBootState)
        assertNull("no device-locked under software attestation", f.deviceLocked)
    }

    @Test fun api28_challenge_is_still_readable() {
        // Element [4] (attestationChallenge) parses regardless of attestation version,
        // which is what makes enroll freshness work on minSdk.
        val chal = Attestation.challenge(leaf())
        assertEquals("32-byte challenge", 32, chal.size)
    }
}
