package io.ssemaj.deviceintelligence.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM unit tests for [KeyDescriptionParser].
 *
 * Synthetic DER fixtures are built with [DerBuilder] rather than
 * pulled from a real device — the goal is to exercise every code
 * path in the parser (multi-byte context tags, tee-vs-software
 * field merging, malformed inputs, missing optional fields)
 * deterministically. Real-device golden vectors will be added
 * later as opaque base64 fixtures once captured.
 */
class KeyDescriptionParserTest {

    // KeyDescription field tag numbers — duplicated here to match
    // exactly what the parser expects (kept private in the parser).
    private companion object {
        const val TAG_ROOT_OF_TRUST = 704
        const val TAG_OS_VERSION = 705
        const val TAG_OS_PATCH_LEVEL = 706
        const val TAG_ATTESTATION_APPLICATION_ID = 709
        const val TAG_VENDOR_PATCH_LEVEL = 718
        const val TAG_BOOT_PATCH_LEVEL = 719
    }

    @Test
    fun `parses fully populated TEE attestation`() {
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 4,
                attestationSecurityLevel = 1, // TrustedEnvironment
                keymasterVersion = 41,
                keymasterSecurityLevel = 1,
                challenge = byteArrayOf(0x10, 0x20, 0x30),
                teeEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ROOT_OF_TRUST,
                        DerBuilder.seq(
                            DerBuilder.octet(byteArrayOf(0xAA.toByte(), 0xBB.toByte())),
                            DerBuilder.bool(true),
                            DerBuilder.enumerated(0), // Verified
                        ),
                    ),
                    DerBuilder.ctxExplicit(TAG_OS_VERSION, DerBuilder.int(140000)),
                    DerBuilder.ctxExplicit(TAG_OS_PATCH_LEVEL, DerBuilder.int(20260301)),
                    DerBuilder.ctxExplicit(TAG_VENDOR_PATCH_LEVEL, DerBuilder.int(20260205)),
                    DerBuilder.ctxExplicit(TAG_BOOT_PATCH_LEVEL, DerBuilder.int(20260205)),
                ),
                softwareEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ATTESTATION_APPLICATION_ID,
                        DerBuilder.octet(
                            buildAttestationApplicationId(
                                packageName = "com.example.app",
                                signatureDigests = listOf(
                                    byteArrayOf(0x01, 0x02, 0x03),
                                    byteArrayOf(0xFF.toByte()),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull("expected parse to succeed", parsed)
        parsed!!

        assertEquals(4, parsed.attestationVersion)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, parsed.attestationSecurityLevel)
        assertEquals(41, parsed.keymasterVersion)
        assertEquals(SecurityLevel.TRUSTED_ENVIRONMENT, parsed.keymasterSecurityLevel)
        assertTrue(byteArrayOf(0x10, 0x20, 0x30).contentEquals(parsed.attestationChallenge))
        assertEquals(VerifiedBootState.VERIFIED, parsed.verifiedBootState)
        assertEquals(true, parsed.deviceLocked)
        assertTrue(
            byteArrayOf(0xAA.toByte(), 0xBB.toByte()).contentEquals(parsed.verifiedBootKey),
        )
        assertEquals(140000, parsed.osVersion)
        assertEquals(20260301, parsed.osPatchLevel)
        assertEquals(20260205, parsed.vendorPatchLevel)
        assertEquals(20260205, parsed.bootPatchLevel)
        assertEquals("com.example.app", parsed.attestedPackageName)
        assertEquals(2, parsed.attestedSignerDigestsHex.size)
        assertEquals("010203", parsed.attestedSignerDigestsHex[0])
        assertEquals("ff", parsed.attestedSignerDigestsHex[1])
    }

    @Test
    fun `parses StrongBox security level`() {
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 100,
                attestationSecurityLevel = 2, // StrongBox
                keymasterVersion = 100,
                keymasterSecurityLevel = 2,
                challenge = ByteArray(32) { it.toByte() },
                teeEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ROOT_OF_TRUST,
                        DerBuilder.seq(
                            DerBuilder.octet(ByteArray(32) { 0x55 }),
                            DerBuilder.bool(true),
                            DerBuilder.enumerated(0),
                        ),
                    ),
                ),
                softwareEnforced = DerBuilder.seq(),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull(parsed)
        assertEquals(SecurityLevel.STRONG_BOX, parsed!!.attestationSecurityLevel)
        assertEquals(SecurityLevel.STRONG_BOX, parsed.keymasterSecurityLevel)
        assertEquals(VerifiedBootState.VERIFIED, parsed.verifiedBootState)
        assertEquals(true, parsed.deviceLocked)
    }

    @Test
    fun `parses degenerate software-only attestation`() {
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 4,
                attestationSecurityLevel = 0, // Software
                keymasterVersion = 41,
                keymasterSecurityLevel = 0,
                challenge = byteArrayOf(),
                teeEnforced = DerBuilder.seq(),
                softwareEnforced = DerBuilder.seq(),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull(parsed)
        assertEquals(SecurityLevel.SOFTWARE, parsed!!.attestationSecurityLevel)
        assertNull(parsed.verifiedBootState)
        assertNull(parsed.deviceLocked)
        assertNull(parsed.verifiedBootKey)
        assertNull(parsed.osPatchLevel)
        assertNull(parsed.vendorPatchLevel)
        assertNull(parsed.bootPatchLevel)
        assertNull(parsed.attestedPackageName)
        assertEquals(emptyList<String>(), parsed.attestedSignerDigestsHex)
    }

    @Test
    fun `parses unverified-boot, unlocked device`() {
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 4,
                attestationSecurityLevel = 1,
                keymasterVersion = 41,
                keymasterSecurityLevel = 1,
                challenge = byteArrayOf(0x42),
                teeEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ROOT_OF_TRUST,
                        DerBuilder.seq(
                            DerBuilder.octet(byteArrayOf(0x00)),
                            DerBuilder.bool(false),
                            DerBuilder.enumerated(2), // Unverified
                        ),
                    ),
                    DerBuilder.ctxExplicit(TAG_OS_PATCH_LEVEL, DerBuilder.int(20240101)),
                ),
                softwareEnforced = DerBuilder.seq(),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull(parsed)
        assertEquals(VerifiedBootState.UNVERIFIED, parsed!!.verifiedBootState)
        assertEquals(false, parsed.deviceLocked)
        assertEquals(20240101, parsed.osPatchLevel)
    }

    @Test
    fun `unknown context tags inside AuthorizationList are skipped`() {
        // Tag [42] with a NULL payload is not in our switch — must be
        // walked over silently without breaking subsequent fields.
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 4,
                attestationSecurityLevel = 1,
                keymasterVersion = 41,
                keymasterSecurityLevel = 1,
                challenge = byteArrayOf(),
                teeEnforced = DerBuilder.seq(
                    // unknown short-form tag [42] with INTEGER content
                    DerBuilder.ctxExplicit(42, DerBuilder.int(7)),
                    DerBuilder.ctxExplicit(TAG_OS_PATCH_LEVEL, DerBuilder.int(20260101)),
                ),
                softwareEnforced = DerBuilder.seq(),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull(parsed)
        assertEquals(20260101, parsed!!.osPatchLevel)
    }

    @Test
    fun `tee-enforced wins over software-enforced for boot fields`() {
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 4,
                attestationSecurityLevel = 1,
                keymasterVersion = 41,
                keymasterSecurityLevel = 1,
                challenge = byteArrayOf(),
                teeEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ROOT_OF_TRUST,
                        DerBuilder.seq(
                            DerBuilder.octet(byteArrayOf(0x11)),
                            DerBuilder.bool(true),
                            DerBuilder.enumerated(0), // Verified
                        ),
                    ),
                ),
                softwareEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ROOT_OF_TRUST,
                        DerBuilder.seq(
                            DerBuilder.octet(byteArrayOf(0x99.toByte())),
                            DerBuilder.bool(false),
                            DerBuilder.enumerated(2), // Unverified — should be ignored
                        ),
                    ),
                ),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull(parsed)
        // teeEnforced wins.
        assertEquals(VerifiedBootState.VERIFIED, parsed!!.verifiedBootState)
        assertEquals(true, parsed.deviceLocked)
        assertTrue(byteArrayOf(0x11).contentEquals(parsed.verifiedBootKey))
    }

    @Test
    fun `software-enforced wins for attestationApplicationId`() {
        val ext = wrapExtensionValue(
            buildKeyDescription(
                attestationVersion = 4,
                attestationSecurityLevel = 1,
                keymasterVersion = 41,
                keymasterSecurityLevel = 1,
                challenge = byteArrayOf(),
                teeEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ATTESTATION_APPLICATION_ID,
                        DerBuilder.octet(
                            buildAttestationApplicationId(
                                packageName = "com.tee.wrong",
                                signatureDigests = listOf(byteArrayOf(0xEE.toByte())),
                            ),
                        ),
                    ),
                ),
                softwareEnforced = DerBuilder.seq(
                    DerBuilder.ctxExplicit(
                        TAG_ATTESTATION_APPLICATION_ID,
                        DerBuilder.octet(
                            buildAttestationApplicationId(
                                packageName = "com.example.right",
                                signatureDigests = listOf(byteArrayOf(0xCC.toByte())),
                            ),
                        ),
                    ),
                ),
            ),
        )

        val parsed = KeyDescriptionParser.parse(ext)
        assertNotNull(parsed)
        assertEquals("com.example.right", parsed!!.attestedPackageName)
        assertEquals(listOf("cc"), parsed.attestedSignerDigestsHex)
    }

    @Test
    fun `garbage bytes return null`() {
        assertNull(KeyDescriptionParser.parse(ByteArray(0)))
        assertNull(KeyDescriptionParser.parse(byteArrayOf(0xFF.toByte(), 0xFF.toByte())))
        assertNull(
            KeyDescriptionParser.parse(
                byteArrayOf(0x30, 0x82.toByte(), 0xFF.toByte(), 0xFF.toByte()),
            ),
        )
    }

    @Test
    fun `length-overflow malformed extension yields null`() {
        // OCTET STRING with a long-form length claiming 4MB but no payload.
        val malformed = byteArrayOf(0x04, 0x83.toByte(), 0x40, 0x00, 0x00)
        assertNull(KeyDescriptionParser.parse(malformed))
    }

    // ---- isCborEatFormat (KeyMint 200+ / Android 14+) --------------------

    @Test
    fun `isCborEatFormat returns false for legacy ASN_1 SEQUENCE content`() {
        // OCTET STRING wrapping an ASN.1 SEQUENCE (0x30) — the legacy
        // KeyDescription shape every Android < 14 device produces.
        val inner = byteArrayOf(0x30, 0x00) // empty SEQUENCE
        val wrapped = byteArrayOf(0x04, inner.size.toByte()) + inner
        assertEquals(false, KeyDescriptionParser.isCborEatFormat(wrapped))
    }

    @Test
    fun `isCborEatFormat trips on CBOR map header byte after OCTET STRING unwrap`() {
        // CBOR major type 5 (map): the inner content's first byte is
        // 0xA0..0xBF. 0xA3 = small-count CBOR map (3 entries).
        val inner = byteArrayOf(0xA3.toByte(), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
        val wrapped = byteArrayOf(0x04, inner.size.toByte()) + inner
        assertEquals(true, KeyDescriptionParser.isCborEatFormat(wrapped))
    }

    @Test
    fun `isCborEatFormat trips on CBOR indefinite-length map header`() {
        // 0xBF = CBOR indefinite-length map. Also major-type 5.
        val inner = byteArrayOf(0xBF.toByte(), 0xFF.toByte())
        val wrapped = byteArrayOf(0x04, inner.size.toByte()) + inner
        assertEquals(true, KeyDescriptionParser.isCborEatFormat(wrapped))
    }

    @Test
    fun `isCborEatFormat returns false for empty input`() {
        assertEquals(false, KeyDescriptionParser.isCborEatFormat(ByteArray(0)))
    }

    @Test
    fun `isCborEatFormat returns false for garbage bytes`() {
        // Not a valid OCTET STRING — outer unwrap fails, returns false.
        assertEquals(
            false,
            KeyDescriptionParser.isCborEatFormat(byteArrayOf(0xFF.toByte(), 0xFF.toByte())),
        )
    }

    // ---- fixture builders -------------------------------------------------

    /**
     * Build a `KeyDescription` SEQUENCE wrapped in the OCTET STRING
     * envelope that [java.security.cert.X509Certificate.getExtensionValue]
     * returns at runtime. Mirrors the parser's expected input shape.
     */
    private fun buildKeyDescription(
        attestationVersion: Int,
        attestationSecurityLevel: Int,
        keymasterVersion: Int,
        keymasterSecurityLevel: Int,
        challenge: ByteArray,
        teeEnforced: ByteArray,
        softwareEnforced: ByteArray,
    ): ByteArray = DerBuilder.seq(
        DerBuilder.int(attestationVersion),
        DerBuilder.enumerated(attestationSecurityLevel),
        DerBuilder.int(keymasterVersion),
        DerBuilder.enumerated(keymasterSecurityLevel),
        DerBuilder.octet(challenge),
        DerBuilder.octet(byteArrayOf()), // uniqueId — always empty for our purposes
        softwareEnforced,
        teeEnforced,
    )

    private fun wrapExtensionValue(keyDescription: ByteArray): ByteArray {
        // X509Certificate.getExtensionValue returns the inner OCTET
        // STRING wrapping the actual extension bytes.
        return DerBuilder.octet(keyDescription)
    }

    /**
     * Build the raw bytes of an `attestationApplicationId` OCTET STRING.
     *
     * ```
     * AttestationApplicationId ::= SEQUENCE {
     *     packageInfos     SET OF AttestationPackageInfo,
     *     signatureDigests SET OF OCTET STRING
     * }
     * AttestationPackageInfo ::= SEQUENCE {
     *     packageName  OCTET STRING,
     *     version      INTEGER
     * }
     * ```
     */
    private fun buildAttestationApplicationId(
        packageName: String,
        signatureDigests: List<ByteArray>,
    ): ByteArray {
        val packageInfo = DerBuilder.seq(
            DerBuilder.octet(packageName.toByteArray(Charsets.UTF_8)),
            DerBuilder.int(1),
        )
        val packageInfosSet = DerBuilder.set(packageInfo)
        val signatureDigestsSet = DerBuilder.set(
            *signatureDigests.map { DerBuilder.octet(it) }.toTypedArray(),
        )
        return DerBuilder.seq(packageInfosSet, signatureDigestsSet)
    }
}
