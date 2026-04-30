package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.math.BigInteger
import java.security.cert.CertificateException
import java.util.Calendar
import java.util.Date
import java.util.TimeZone

@Suppress("UnusedPrivateMember") // helpers retained for future cases

/**
 * Pure-JVM coverage for [ChainValidator].
 *
 * Each function is exercised with at least one passing case (asserts
 * `null`) and at least one tripping case (asserts a stable subreason
 * code). The tripping subreasons are the wire vocabulary backends key
 * on, so any unintentional rename here is a contract break and would
 * fail this suite.
 *
 * Real cert chains from real TEE keygens are exercised end-to-end by
 * the sample app on instrumented hardware; the unit tests here use
 * [FakeX509Certificate] so they run in milliseconds without a device
 * and without an `AndroidKeyStore` provider.
 */
class ChainValidatorTest {

    // ---- helpers ----------------------------------------------------------

    private fun utc(year: Int, month: Int, day: Int): Date =
        Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply {
            clear()
            set(year, month - 1, day, 0, 0, 0)
        }.time

    private fun cert(
        notBefore: Date = utc(2026, 4, 1),
        notAfter: Date = utc(2027, 4, 1),
        publicKeyBytes: ByteArray = byteArrayOf(1, 2, 3),
        encoded: ByteArray = byteArrayOf(0x30, 0x01, 0x00),
        serial: Long = 1L,
        verify: (java.security.PublicKey) -> Unit = { /* default ok */ },
    ): FakeX509Certificate = FakeX509Certificate(
        notBefore = notBefore,
        notAfter = notAfter,
        publicKey = FakePublicKey(publicKeyBytes),
        encoded = encoded,
        serial = BigInteger.valueOf(serial),
        verifyResult = verify,
    )

    private fun parsed(
        challenge: ByteArray = byteArrayOf(),
        osPatchLevel: Int? = null,
    ): ParsedKeyDescription = ParsedKeyDescription(
        attestationVersion = 4,
        attestationSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        keymasterVersion = 4,
        keymasterSecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT,
        attestationChallenge = challenge,
        verifiedBootState = null,
        deviceLocked = null,
        verifiedBootKey = null,
        osVersion = null,
        osPatchLevel = osPatchLevel,
        vendorPatchLevel = null,
        bootPatchLevel = null,
        attestedPackageName = null,
        attestationApplicationIdRaw = null,
        attestedSignerDigestsHex = emptyList(),
    )

    private fun success(
        nonce: ByteArray = ByteArray(32) { 0 },
        leaf: FakeX509Certificate = cert(),
        rest: List<FakeX509Certificate> = emptyList(),
        parsed: ParsedKeyDescription? = null,
        keyStorePubKey: ByteArray? = leaf.publicKey.encoded,
    ): AttestationResult.Success = AttestationResult.Success(
        chainB64 = "",
        chainLength = 1 + rest.size,
        parsed = parsed,
        rawCerts = listOf<java.security.cert.X509Certificate>(leaf) + rest,
        keyStorePublicKeyEncoded = keyStorePubKey,
        nonce = nonce,
    )

    // ---- validateStructure ------------------------------------------------

    @Test
    fun `validateStructure passes on a 2-cert chain`() {
        assertNull(ChainValidator.validateStructure(listOf(cert(), cert(serial = 2))))
    }

    @Test
    fun `validateStructure trips on empty chain`() {
        assertEquals("chain_empty", ChainValidator.validateStructure(emptyList()))
    }

    @Test
    fun `validateStructure trips on single-cert chain`() {
        assertEquals("chain_too_short", ChainValidator.validateStructure(listOf(cert())))
    }

    // ---- verifyChainSignatures -------------------------------------------

    @Test
    fun `verifyChainSignatures passes when each cert verifies`() {
        // Each verify lambda is a no-op = success.
        val leaf = cert(serial = 1)
        val root = cert(serial = 2)
        assertNull(ChainValidator.verifyChainSignatures(listOf(leaf, root)))
    }

    @Test
    fun `verifyChainSignatures trips when an intermediate signature fails`() {
        val leaf = cert(
            serial = 1,
            verify = { throw CertificateException("bad sig") },
        )
        val root = cert(serial = 2)
        assertEquals(
            "chain_signature_invalid",
            ChainValidator.verifyChainSignatures(listOf(leaf, root)),
        )
    }

    @Test
    fun `verifyChainSignatures trips when root is not self-signed`() {
        val leaf = cert(serial = 1)
        val root = cert(
            serial = 2,
            verify = { throw CertificateException("not self signed") },
        )
        assertEquals(
            "chain_root_not_self_signed",
            ChainValidator.verifyChainSignatures(listOf(leaf, root)),
        )
    }

    @Test
    fun `verifyChainSignatures trips on empty chain`() {
        assertEquals("chain_empty", ChainValidator.verifyChainSignatures(emptyList()))
    }

    // Note: an earlier `validityPeriodsNested` validator enforced strict
    // notBefore/notAfter nesting between intermediates and got removed —
    // real OEM TEE chains (Spreadtrum/UNISOC, older Tensor batches) trip
    // it in opposite directions on devices reporting MEETS_STRONG_INTEGRITY
    // with verified-boot Verified + bootloader-locked. See ChainValidator
    // for the full removal rationale.

    // ---- challengeEchoes -------------------------------------------------

    @Test
    fun `challengeEchoes passes when nonce matches`() {
        val nonce = byteArrayOf(1, 2, 3, 4)
        assertNull(ChainValidator.challengeEchoes(parsed(challenge = nonce), nonce))
    }

    @Test
    fun `challengeEchoes trips when nonce differs`() {
        val sent = byteArrayOf(1, 2, 3, 4)
        val attested = byteArrayOf(9, 9, 9, 9)
        assertEquals(
            "challenge_not_echoed",
            ChainValidator.challengeEchoes(parsed(challenge = attested), sent),
        )
    }

    @Test
    fun `challengeEchoes defers when parsed is null`() {
        assertNull(ChainValidator.challengeEchoes(null, byteArrayOf(1)))
    }

    // ---- freshnessAcrossAttestations -------------------------------------
    //
    // Only checks pubkey / challenge identity. Serial-identical and
    // raw-leaf-identical are deliberately NOT compared: KeyMint always
    // sets serial=1, and any leaf-encoding difference reduces to a
    // pubkey-or-challenge difference anyway.

    @Test
    fun `freshnessAcrossAttestations passes when pubkeys and challenges differ`() {
        // Same KeyMint serial=1 default on both — must not trip on its
        // own.
        val a = success(
            nonce = byteArrayOf(1),
            leaf = cert(serial = 1, publicKeyBytes = byteArrayOf(10)),
            parsed = parsed(challenge = byteArrayOf(1)),
        )
        val b = success(
            nonce = byteArrayOf(2),
            leaf = cert(serial = 1, publicKeyBytes = byteArrayOf(20)),
            parsed = parsed(challenge = byteArrayOf(2)),
        )
        assertNull(ChainValidator.freshnessAcrossAttestations(a, b))
    }

    @Test
    fun `freshnessAcrossAttestations trips on identical pubkeys`() {
        val pk = byteArrayOf(7, 7, 7)
        val a = success(leaf = cert(serial = 1, publicKeyBytes = pk))
        val b = success(leaf = cert(serial = 1, publicKeyBytes = pk))
        assertEquals(
            "freshness_pubkey_identical",
            ChainValidator.freshnessAcrossAttestations(a, b),
        )
    }

    @Test
    fun `freshnessAcrossAttestations trips on identical challenges`() {
        val ch = byteArrayOf(5, 5, 5)
        val a = success(
            leaf = cert(serial = 1, publicKeyBytes = byteArrayOf(10)),
            parsed = parsed(challenge = ch),
        )
        val b = success(
            leaf = cert(serial = 1, publicKeyBytes = byteArrayOf(20)),
            parsed = parsed(challenge = ch),
        )
        assertEquals(
            "freshness_challenge_identical",
            ChainValidator.freshnessAcrossAttestations(a, b),
        )
    }

    // ---- leafPubKeyMatchesKeystoreKey ------------------------------------

    @Test
    fun `leafPubKeyMatchesKeystoreKey passes when matching`() {
        val pk = byteArrayOf(0xA, 0xB, 0xC)
        val leaf = cert(publicKeyBytes = pk)
        assertNull(ChainValidator.leafPubKeyMatchesKeystoreKey(leaf, pk))
    }

    @Test
    fun `leafPubKeyMatchesKeystoreKey trips when mismatching`() {
        val leaf = cert(publicKeyBytes = byteArrayOf(1))
        assertEquals(
            "leaf_pubkey_mismatch",
            ChainValidator.leafPubKeyMatchesKeystoreKey(leaf, byteArrayOf(2)),
        )
    }

    @Test
    fun `leafPubKeyMatchesKeystoreKey defers when keystore key unavailable`() {
        // Null keystore pubkey means we couldn't read it (defensive
        // path) — defer rather than trip.
        assertNull(ChainValidator.leafPubKeyMatchesKeystoreKey(cert(), null))
    }

}
