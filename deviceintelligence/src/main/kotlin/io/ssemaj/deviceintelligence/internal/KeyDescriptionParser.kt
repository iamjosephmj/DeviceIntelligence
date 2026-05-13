package io.ssemaj.deviceintelligence.internal

/**
 * Parsed view of the Android Keystore key-attestation extension
 * (`KeyDescription`, OID `1.3.6.1.4.1.11129.2.1.17`).
 *
 * Every field is nullable / defaultable on purpose: the parser is
 * intentionally lossy on malformed or vendor-quirky inputs so that
 * partial parses still produce useful telemetry instead of dropping
 * the whole extension.
 *
 * Field semantics:
 *  - [attestationSecurityLevel] / [keymasterSecurityLevel]: who signed
 *    the cert (Software vs TEE vs StrongBox). The SecurityLevel value
 *    is the single most important field for trust tier derivation.
 *  - [verifiedBootState] + [deviceLocked] + [verifiedBootKey]: from
 *    the `rootOfTrust` block. Together describe whether the bootloader
 *    is OEM-locked and whether the running boot image was signed by
 *    the expected OEM key.
 *  - [osVersion] / [osPatchLevel] / [vendorPatchLevel] / [bootPatchLevel]:
 *    patch dates the TEE believes the OS is at. Useful for the strong-
 *    integrity tier and for spotting "claims to be patched but isn't".
 *  - [attestedPackageName] + [attestedSignerDigestsHex]: the TEE's
 *    independent view of which package + signer owns the attested key.
 *    Cross-checked against the runtime values to derive `app_recognition`.
 */
internal data class ParsedKeyDescription(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: ByteArray,
    val verifiedBootState: VerifiedBootState?,
    val deviceLocked: Boolean?,
    val verifiedBootKey: ByteArray?,
    val osVersion: Int?,
    val osPatchLevel: Int?,
    val vendorPatchLevel: Int?,
    val bootPatchLevel: Int?,
    val attestedPackageName: String?,
    val attestationApplicationIdRaw: ByteArray?,
    val attestedSignerDigestsHex: List<String>,
) {
    // ByteArray fields don't compare structurally by default — we don't
    // rely on equality here, but generated equals/hashCode would be
    // misleading. Suppress the lint by overriding to identity, matching
    // how the rest of the codebase handles raw byte payloads.
    override fun equals(other: Any?): Boolean = this === other
    override fun hashCode(): Int = System.identityHashCode(this)
}

/**
 * `SecurityLevel` enum from the KeyDescription schema. Wire spelling
 * matches Google's documentation so it appears verbatim in
 * `Finding.details` (consumers grep for it).
 */
internal enum class SecurityLevel(val wire: String) {
    SOFTWARE("Software"),
    TRUSTED_ENVIRONMENT("TrustedEnvironment"),
    STRONG_BOX("StrongBox"),
    UNKNOWN("Unknown"),
    ;

    companion object {
        fun fromRaw(raw: Int): SecurityLevel = when (raw) {
            0 -> SOFTWARE
            1 -> TRUSTED_ENVIRONMENT
            2 -> STRONG_BOX
            else -> UNKNOWN
        }
    }
}

/**
 * `VerifiedBootState` enum from the KeyDescription `rootOfTrust`
 * block. Wire spelling again matches Google's docs verbatim.
 */
internal enum class VerifiedBootState(val wire: String) {
    VERIFIED("Verified"),
    SELF_SIGNED("SelfSigned"),
    UNVERIFIED("Unverified"),
    FAILED("Failed"),
    UNKNOWN("Unknown"),
    ;

    companion object {
        fun fromRaw(raw: Int): VerifiedBootState = when (raw) {
            0 -> VERIFIED
            1 -> SELF_SIGNED
            2 -> UNVERIFIED
            3 -> FAILED
            else -> UNKNOWN
        }
    }
}

/**
 * Hand-rolled DER walker for the Android Keystore key-attestation
 * extension (`1.3.6.1.4.1.11129.2.1.17`).
 *
 * Why hand-rolled: every transitive dependency on a security library
 * is one more attack surface and a few more KB of dex — DeviceIntelligence's
 * stated posture (see [TelemetryJson]'s header comment). BouncyCastle
 * pulls in megabytes; `java.security.cert.X509Certificate.getExtensionValue`
 * gives us the raw extension bytes for free, after which the parsing
 * here is small, focused, and inspectable.
 *
 * Coverage: only the fields the F14 detector actually surfaces in
 * its `Finding` details. Unknown / unhandled tags inside the
 * `AuthorizationList` are skipped silently rather than failing the
 * whole parse.
 *
 * Defensive: any individual field that fails to parse is omitted
 * from the result (set to null / empty). The parser does NOT abort
 * on a bad single field. If the top-level structure itself is
 * malformed, the parser returns null and the detector falls back to
 * shipping the raw chain bytes only.
 */
internal object KeyDescriptionParser {

    /** OID of the KeyDescription extension. Use as `Cert.getExtensionValue(OID)`. */
    const val OID: String = "1.3.6.1.4.1.11129.2.1.17"

    // Universal ASN.1 tag numbers we care about.
    private const val TAG_BOOLEAN = 1
    private const val TAG_INTEGER = 2
    private const val TAG_OCTET_STRING = 4
    private const val TAG_ENUMERATED = 10
    private const val TAG_SEQUENCE = 16
    private const val TAG_SET = 17

    // AuthorizationList entries are all context-specific [N] EXPLICIT.
    private const val TAG_ROOT_OF_TRUST = 704
    private const val TAG_OS_VERSION = 705
    private const val TAG_OS_PATCH_LEVEL = 706
    private const val TAG_ATTESTATION_APPLICATION_ID = 709
    private const val TAG_VENDOR_PATCH_LEVEL = 718
    private const val TAG_BOOT_PATCH_LEVEL = 719

    /**
     * Parse the raw extension value as returned by
     * [java.security.cert.X509Certificate.getExtensionValue]. That value is
     * itself a DER-encoded OCTET STRING wrapping the actual KeyDescription
     * SEQUENCE — we unwrap one layer here.
     *
     * Returns null when the inner content is **not** a legacy ASN.1
     * `KeyDescription` SEQUENCE. The most common reason for that on
     * Android 14+ devices is CBOR-EAT format — call [isCborEatFormat]
     * to disambiguate.
     */
    fun parse(extensionValue: ByteArray): ParsedKeyDescription? = try {
        val outer = Reader(extensionValue)
        val unwrapped = outer.readUniversal(TAG_OCTET_STRING) ?: return null
        parseTopLevel(unwrapped)
    } catch (_: Throwable) {
        null
    }

    /**
     * Heuristic: does this extension value look like CBOR-EAT rather
     * than the legacy ASN.1 `KeyDescription`? After unwrapping the
     * outer DER OCTET STRING, a legacy KeyDescription's inner content
     * starts with `0x30` (ASN.1 SEQUENCE tag); a CBOR-EAT inner
     * content starts with a CBOR map header byte in the range
     * `0xA0`–`0xBF` (major type 5).
     *
     * KeyMint 200+ on newer Android can emit attestation in CBOR
     * EAT format; on those devices [parse] returns null because the
     * DER walker can't make sense of CBOR bytes. This helper lets
     * the caller distinguish "extension is malformed" from
     * "extension is in a format we don't fully decode yet" so the
     * wire can carry the right `Finding` kind.
     *
     * Full CBOR-EAT field-level parsing (verified-boot state,
     * device-locked, OS patch level, attested-application-id) is
     * tracked for a follow-up minor — it requires a CBOR decoder
     * dependency or a careful hand-roll, plus on-device validation
     * against a Pixel 8/9 RKP-provisioned chain to confirm tag
     * mappings.
     */
    fun isCborEatFormat(extensionValue: ByteArray): Boolean {
        return try {
            val outer = Reader(extensionValue)
            val unwrapped = outer.readUniversal(TAG_OCTET_STRING)
                ?: return false
            if (unwrapped.isEmpty()) return false
            val first = unwrapped[0].toInt() and 0xFF
            // CBOR major type 5 (map): high bits 101xxxxx → 0xA0..0xBF.
            first in 0xA0..0xBF
        } catch (_: Throwable) {
            false
        }
    }

    private fun parseTopLevel(blob: ByteArray): ParsedKeyDescription? {
        val r = Reader(blob)
        val seq = r.readUniversal(TAG_SEQUENCE) ?: return null
        val s = Reader(seq)

        val attestationVersion = s.readUniversalInt(TAG_INTEGER) ?: return null
        val attestationSecLevel = s.readUniversalEnum() ?: 0
        val keymasterVersion = s.readUniversalInt(TAG_INTEGER) ?: return null
        val keymasterSecLevel = s.readUniversalEnum() ?: 0
        val attestationChallenge = s.readUniversal(TAG_OCTET_STRING) ?: ByteArray(0)
        // uniqueId — usually empty, never useful to surface; skip.
        s.readUniversal(TAG_OCTET_STRING)
        val swEnforced = s.readUniversal(TAG_SEQUENCE) ?: ByteArray(0)
        val teeEnforced = s.readUniversal(TAG_SEQUENCE) ?: ByteArray(0)

        val sw = parseAuthList(swEnforced)
        val tee = parseAuthList(teeEnforced)

        // teeEnforced wins on conflict — it's the more trustworthy of
        // the two lists (the TEE itself populates it, while
        // softwareEnforced is filled in by the framework on the way down).
        // For attestationApplicationId the convention is reversed — that
        // field is always set by the framework, not the TEE — so prefer sw.
        return ParsedKeyDescription(
            attestationVersion = attestationVersion,
            attestationSecurityLevel = SecurityLevel.fromRaw(attestationSecLevel),
            keymasterVersion = keymasterVersion,
            keymasterSecurityLevel = SecurityLevel.fromRaw(keymasterSecLevel),
            attestationChallenge = attestationChallenge,
            verifiedBootState = tee.verifiedBootState ?: sw.verifiedBootState,
            deviceLocked = tee.deviceLocked ?: sw.deviceLocked,
            verifiedBootKey = tee.verifiedBootKey ?: sw.verifiedBootKey,
            osVersion = tee.osVersion ?: sw.osVersion,
            osPatchLevel = tee.osPatchLevel ?: sw.osPatchLevel,
            vendorPatchLevel = tee.vendorPatchLevel ?: sw.vendorPatchLevel,
            bootPatchLevel = tee.bootPatchLevel ?: sw.bootPatchLevel,
            attestedPackageName = sw.attestedPackageName ?: tee.attestedPackageName,
            attestationApplicationIdRaw = sw.attestationApplicationIdRaw
                ?: tee.attestationApplicationIdRaw,
            attestedSignerDigestsHex = sw.attestedSignerDigestsHex.ifEmpty {
                tee.attestedSignerDigestsHex
            },
        )
    }

    /**
     * Result of parsing one `AuthorizationList`. A KeyDescription has
     * two — `softwareEnforced` and `teeEnforced` — that we merge in
     * [parseTopLevel].
     */
    private data class AuthList(
        val verifiedBootState: VerifiedBootState? = null,
        val deviceLocked: Boolean? = null,
        val verifiedBootKey: ByteArray? = null,
        val osVersion: Int? = null,
        val osPatchLevel: Int? = null,
        val vendorPatchLevel: Int? = null,
        val bootPatchLevel: Int? = null,
        val attestedPackageName: String? = null,
        val attestationApplicationIdRaw: ByteArray? = null,
        val attestedSignerDigestsHex: List<String> = emptyList(),
    )

    private fun parseAuthList(blob: ByteArray): AuthList {
        if (blob.isEmpty()) return AuthList()
        var verifiedBootState: VerifiedBootState? = null
        var deviceLocked: Boolean? = null
        var verifiedBootKey: ByteArray? = null
        var osVersion: Int? = null
        var osPatchLevel: Int? = null
        var vendorPatchLevel: Int? = null
        var bootPatchLevel: Int? = null
        var attestedPackageName: String? = null
        var attestationApplicationIdRaw: ByteArray? = null
        var attestedSignerDigestsHex: List<String> = emptyList()

        val r = Reader(blob)
        while (r.remaining > 0) {
            val tag = r.readAnyTag() ?: break
            // All AuthorizationList entries are context-specific.
            if (tag.tagClass != CLASS_CONTEXT) continue
            when (tag.tagNum) {
                TAG_ROOT_OF_TRUST -> {
                    val rot = parseRootOfTrust(tag.value)
                    if (rot != null) {
                        verifiedBootKey = rot.verifiedBootKey
                        deviceLocked = rot.deviceLocked
                        verifiedBootState = rot.verifiedBootState
                    }
                }
                TAG_OS_VERSION -> osVersion = readInnerInt(tag.value)
                TAG_OS_PATCH_LEVEL -> osPatchLevel = readInnerInt(tag.value)
                TAG_VENDOR_PATCH_LEVEL -> vendorPatchLevel = readInnerInt(tag.value)
                TAG_BOOT_PATCH_LEVEL -> bootPatchLevel = readInnerInt(tag.value)
                TAG_ATTESTATION_APPLICATION_ID -> {
                    val raw = readInnerOctetString(tag.value)
                    if (raw != null) {
                        attestationApplicationIdRaw = raw
                        val parsed = parseAttestationApplicationId(raw)
                        if (parsed != null) {
                            attestedPackageName = parsed.first
                            attestedSignerDigestsHex = parsed.second
                        }
                    }
                }
            }
        }

        return AuthList(
            verifiedBootState = verifiedBootState,
            deviceLocked = deviceLocked,
            verifiedBootKey = verifiedBootKey,
            osVersion = osVersion,
            osPatchLevel = osPatchLevel,
            vendorPatchLevel = vendorPatchLevel,
            bootPatchLevel = bootPatchLevel,
            attestedPackageName = attestedPackageName,
            attestationApplicationIdRaw = attestationApplicationIdRaw,
            attestedSignerDigestsHex = attestedSignerDigestsHex,
        )
    }

    private data class RootOfTrust(
        val verifiedBootKey: ByteArray,
        val deviceLocked: Boolean,
        val verifiedBootState: VerifiedBootState,
    )

    private fun parseRootOfTrust(explicitValue: ByteArray): RootOfTrust? {
        // [704] EXPLICIT — the explicit wrapper means the inner value
        // is a regular SEQUENCE.
        val r = Reader(explicitValue)
        val seq = r.readUniversal(TAG_SEQUENCE) ?: return null
        val s = Reader(seq)
        val verifiedBootKey = s.readUniversal(TAG_OCTET_STRING) ?: return null
        val deviceLocked = s.readUniversalBoolean() ?: return null
        val vbsRaw = s.readUniversalEnum() ?: return null
        // verifiedBootHash (KM4+) is the next field; we don't surface it.
        return RootOfTrust(verifiedBootKey, deviceLocked, VerifiedBootState.fromRaw(vbsRaw))
    }

    private fun readInnerInt(explicitValue: ByteArray): Int? {
        val r = Reader(explicitValue)
        return r.readUniversalInt(TAG_INTEGER)
    }

    private fun readInnerOctetString(explicitValue: ByteArray): ByteArray? {
        val r = Reader(explicitValue)
        return r.readUniversal(TAG_OCTET_STRING)
    }

    /**
     * Parse the inner DER blob of an `attestationApplicationId`
     * extension. Schema:
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
     *
     * Returns `(firstPackageName, allSignatureDigestsHex)` where the
     * digests are lowercase hex (matching the rest of the codebase).
     */
    private fun parseAttestationApplicationId(raw: ByteArray): Pair<String, List<String>>? {
        val r = Reader(raw)
        val seq = r.readUniversal(TAG_SEQUENCE) ?: return null
        val s = Reader(seq)
        val packageInfosSet = s.readUniversal(TAG_SET) ?: return null
        val signatureDigestsSet = s.readUniversal(TAG_SET) ?: ByteArray(0)

        val piReader = Reader(packageInfosSet)
        val firstPi = piReader.readUniversal(TAG_SEQUENCE) ?: return null
        val piInner = Reader(firstPi)
        val packageNameBytes = piInner.readUniversal(TAG_OCTET_STRING) ?: return null
        val packageName = String(packageNameBytes, Charsets.UTF_8)

        val digests = ArrayList<String>(2)
        val sdReader = Reader(signatureDigestsSet)
        while (sdReader.remaining > 0) {
            val d = sdReader.readUniversal(TAG_OCTET_STRING) ?: break
            digests += hexLower(d)
        }

        return packageName to digests
    }

    // ---- minimal DER reader ------------------------------------------------

    private const val CLASS_UNIVERSAL = 0
    private const val CLASS_CONTEXT = 2

    /**
     * One parsed tag-length-value triple. Returned by [Reader.readAnyTag]
     * for callers that need to dispatch on tag number themselves
     * (i.e. the AuthorizationList walker).
     */
    private data class TagInfo(
        val tagClass: Int,
        val constructed: Boolean,
        val tagNum: Int,
        val value: ByteArray,
    )

    /**
     * Tiny stateful DER reader. Walks left-to-right through a byte
     * buffer, consuming tag-length-value blocks. NOT thread-safe;
     * each parse call gets its own instance.
     *
     * Bounds-checked at every step — a malformed length field that
     * would walk past the buffer end yields null rather than an
     * AIOOBE, so the parser as a whole degrades gracefully.
     */
    private class Reader(private val buf: ByteArray) {
        private var pos = 0
        val remaining: Int get() = buf.size - pos

        /**
         * Read the next tag and assert it is a universal tag matching
         * [expectedTagNum] (e.g. SEQUENCE = 16, OCTET STRING = 4).
         * Returns the value bytes on success, null on mismatch / EOF.
         */
        fun readUniversal(expectedTagNum: Int): ByteArray? {
            val savedPos = pos
            val h = readHeader() ?: return null
            if (h.tagClass != CLASS_UNIVERSAL || h.tagNum != expectedTagNum) {
                pos = savedPos
                return null
            }
            val out = buf.copyOfRange(pos, pos + h.length)
            pos += h.length
            return out
        }

        fun readUniversalInt(expectedTagNum: Int): Int? {
            val v = readUniversal(expectedTagNum) ?: return null
            return decodeIntBE(v)
        }

        fun readUniversalEnum(): Int? {
            val v = readUniversal(TAG_ENUMERATED) ?: return null
            return decodeIntBE(v)
        }

        fun readUniversalBoolean(): Boolean? {
            val v = readUniversal(TAG_BOOLEAN) ?: return null
            if (v.isEmpty()) return null
            return v[0].toInt() != 0
        }

        /** Read any tag (universal, application, or context-specific). */
        fun readAnyTag(): TagInfo? {
            val h = readHeader() ?: return null
            val out = buf.copyOfRange(pos, pos + h.length)
            pos += h.length
            return TagInfo(h.tagClass, h.constructed, h.tagNum, out)
        }

        private data class Header(
            val tagClass: Int,
            val constructed: Boolean,
            val tagNum: Int,
            val length: Int,
        )

        private fun readHeader(): Header? {
            if (remaining < 2) return null
            val tagByte = buf[pos++].toInt() and 0xFF
            val tagClass = (tagByte ushr 6) and 0x03
            val constructed = (tagByte and 0x20) != 0
            var tagNum = tagByte and 0x1F
            if (tagNum == 0x1F) {
                // Multi-byte tag form: subsequent bytes carry 7 bits of
                // tag number each, with bit 7 as a continuation flag.
                tagNum = 0
                while (true) {
                    if (remaining < 1) return null
                    val b = buf[pos++].toInt() and 0xFF
                    tagNum = (tagNum shl 7) or (b and 0x7F)
                    if ((b and 0x80) == 0) break
                    // Sanity: AuthorizationList tag numbers are well below 1M.
                    if (tagNum > 0x10_0000) return null
                }
            }
            if (remaining < 1) return null
            val first = buf[pos++].toInt() and 0xFF
            val length: Int = if (first < 0x80) {
                first
            } else {
                val numLen = first and 0x7F
                if (numLen == 0 || numLen > 4 || remaining < numLen) return null
                var n = 0
                repeat(numLen) {
                    n = (n shl 8) or (buf[pos++].toInt() and 0xFF)
                }
                n
            }
            if (length < 0 || length > remaining) return null
            return Header(tagClass, constructed, tagNum, length)
        }
    }

    /**
     * Decode a big-endian two's-complement integer (DER INTEGER /
     * ENUMERATED encoding). Returns null on overflow or empty input.
     * We accept up to 5 bytes to permit a leading 0x00 padding byte
     * on values that would otherwise be interpreted as negative.
     */
    private fun decodeIntBE(b: ByteArray): Int? {
        if (b.isEmpty() || b.size > 5) return null
        var n = 0L
        if (b[0].toInt() < 0) {
            // Negative — sign-extend the high word.
            n = -1L
        }
        for (byte in b) {
            n = (n shl 8) or (byte.toLong() and 0xFF)
        }
        if (n < Int.MIN_VALUE.toLong() || n > Int.MAX_VALUE.toLong()) return null
        return n.toInt()
    }

    // ---- shared helper -----------------------------------------------------

    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun hexLower(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xFF
            out[2 * i] = HEX_CHARS[(b ushr 4) and 0xF]
            out[2 * i + 1] = HEX_CHARS[b and 0xF]
        }
        return String(out)
    }
}
