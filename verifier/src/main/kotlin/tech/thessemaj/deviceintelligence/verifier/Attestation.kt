package tech.thessemaj.deviceintelligence.verifier

import java.security.cert.X509Certificate

/** The TEE's own device-integrity report, read from the attestation extension. */
data class AttestationFields(
    /** 0 Software, 1 TrustedEnvironment, 2 StrongBox. Null when absent or unparseable. */
    val securityLevel: Int?,
    /** 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed. Null when absent or unparseable. */
    val verifiedBootState: Int?,
    /** Whether the bootloader reported itself locked. Null when the field is absent. */
    val deviceLocked: Boolean?,
) {
    /** [securityLevel] as its spec name, or the raw number, or `"?"` when absent. */
    val securityLevelName get() = SECURITY_LEVEL[securityLevel] ?: securityLevel?.toString() ?: "?"

    /** [verifiedBootState] as its spec name, or the raw number, or `"?"` when absent. */
    val bootStateName get() = BOOT_STATE[verifiedBootState] ?: verifiedBootState?.toString() ?: "?"

    companion object {
        /** KeyMint `securityLevel` enum -> spec name. */
        val SECURITY_LEVEL = mapOf(0 to "Software", 1 to "TrustedEnvironment", 2 to "StrongBox")

        /** KeyMint `verifiedBootState` enum -> spec name. */
        val BOOT_STATE = mapOf(0 to "Verified", 1 to "SelfSigned", 2 to "Unverified", 3 to "Failed")
    }
}

/**
 * The app identity KeyMint recorded in the attestation: package names and the
 * SHA-256 digests (lowercase hex) of the APK signing certificates.
 *
 * NOTE this lives in the softwareEnforced authorization list — the platform
 * keystore asserts it, not the TEE. The TEE signs over it so it cannot be altered
 * in transit, but on a device with unverified or unlocked boot the platform could
 * have been patched to lie. Sound exactly when the boot state is sound.
 */
data class AttestedApp(
    /** Every package name sharing the attested UID. Usually one. */
    val packageNames: List<String>,
    /** Lowercase-hex SHA-256 digests of the APK signing certificates. */
    val signatureDigests: List<String>,
)

/**
 * Platform facts the TEE attests: the OS version and the three security patch
 * levels. Unlike Build.VERSION these cannot be faked by a prop spoofer, which is
 * what makes them worth grading on.
 *
 * [osPatchLevel] is YYYYMM (month precision). [vendorPatchLevel] and
 * [bootPatchLevel] are YYYYMMDD. Mixing those granularities is the bug INTEL_0048
 * exists to avoid — see the comparison rule there.
 */
data class AttestedPlatform(
    /** Android release encoded by KeyMint, e.g. `160000` for Android 16. Null if absent. */
    val osVersion: Int?,
    /** System patch level, **YYYYMM** — month precision. Null if absent. */
    val osPatchLevel: Int?,
    /** Vendor image patch level, **YYYYMMDD**. Null if absent. */
    val vendorPatchLevel: Int?,
    /** Boot image patch level, **YYYYMMDD**. Null if absent. */
    val bootPatchLevel: Int?,
)

/**
 * Reads the Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) by a
 * minimal DER walk — a direct port of the helpers in verify_token.py. Two things
 * come out of it: the leaf's attestationChallenge (must equal the server nonce)
 * and the RootOfTrust device-integrity fields (which a rooted device cannot fake
 * without spoofing attestation).
 */
internal object Attestation {
    const val OID = "1.3.6.1.4.1.11129.2.1.17"

    // RootOfTrust lives under an EXPLICIT [704] context tag in the authorization list.
    private val ROOT_OF_TRUST_TAG = byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x40.toByte())

    // attestationApplicationId, EXPLICIT context tag [709] -> 0xBF 0x85 0x45
    // (same high-tag-number form as [704] = 0x40 above).
    private val ATTEST_APP_ID_TAG = byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x45)

    // Platform tags, EXPLICIT context high-tag-number form (same shape as [704] = 0x40):
    // osVersion[705]=0x41, osPatchLevel[706]=0x42, vendorPatchLevel[718]=0x4e,
    // bootPatchLevel[719]=0x4f.
    private val OS_VERSION_TAG     = byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x41)
    private val OS_PATCH_LEVEL_TAG = byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x42)
    private val VENDOR_PATCH_TAG   = byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x4e)
    private val BOOT_PATCH_TAG     = byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x4f)

    // attestationId* device-property tags (KeyMint AuthorizationList EXPLICIT context
    // tags, high-tag-number form 0xBF 0x85 0xNN): brand[710]=46, device[711]=47,
    // product[712]=48, manufacturer[716]=4c, model[717]=4d. Present only when the key
    // was generated with setDevicePropertiesAttestationIncluded(true) (API 31+).
    private val ATTEST_ID: List<Pair<String, ByteArray>> = listOf(
        "brand" to byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x46),
        "device" to byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x47),
        "product" to byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x48),
        "manufacturer" to byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x4c),
        "model" to byteArrayOf(0xbf.toByte(), 0x85.toByte(), 0x4d),
    )

    /** The KeyDescription SEQUENCE DER (unwrapping the extension's outer OCTET STRING). */
    private fun keyDescriptionDer(cert: X509Certificate): ByteArray {
        val raw = cert.getExtensionValue(OID)
            ?: throw IllegalArgumentException("no Android attestation extension on leaf")
        // getExtensionValue returns the extnValue as a DER OCTET STRING wrapping the
        // actual KeyDescription; unwrap that one layer.
        val (octet, _) = Der.readTlv(raw, 0)
        return octet.value
    }

    /** attestationChallenge = KeyDescription element index 4. */
    fun challenge(cert: X509Certificate): ByteArray =
        Der.sequenceElements(keyDescriptionDer(cert))[4].value

    fun fields(cert: X509Certificate): AttestationFields {
        val elems = Der.sequenceElements(keyDescriptionDer(cert))
        val secLevel = elems.getOrNull(1)?.value?.let { if (it.isNotEmpty()) it[0].toInt() and 0xff else null }

        var bootState: Int? = null
        var locked: Boolean? = null
        for (authIdx in intArrayOf(7, 6)) {                 // teeEnforced, then softwareEnforced
            val auth = elems.getOrNull(authIdx) ?: continue
            for (tlv in Der.tlvList(auth.value)) {
                if (tlv.tag.contentEquals(ROOT_OF_TRUST_TAG)) {
                    val (inner, _) = Der.readTlv(tlv.value, 0)   // EXPLICIT -> inner SEQUENCE
                    val rot = Der.tlvList(inner.value)
                    // RootOfTrust { verifiedBootKey, deviceLocked BOOL, verifiedBootState ENUM, ... }
                    rot.getOrNull(1)?.value?.let { if (it.isNotEmpty()) locked = it[0].toInt() != 0 }
                    rot.getOrNull(2)?.value?.let { if (it.isNotEmpty()) bootState = it[0].toInt() and 0xff }
                    break
                }
            }
            if (bootState != null) break
        }
        return AttestationFields(secLevel, bootState, locked)
    }

    /**
     * The TEE-attested device identity (brand/device/product/manufacturer/model),
     * read from the leaf's `attestationId*` tags. Empty map when the key was not
     * generated with device-properties attestation (older devices / not requested).
     * These come from the secure keymaster and reflect the REAL device the keybox
     * belongs to — a spoofer reusing a foreign keybox cannot make them match a faked
     * `Build.*` self-report.
     */
    fun deviceProperties(cert: X509Certificate): Map<String, String> {
        val elems = Der.sequenceElements(keyDescriptionDer(cert))
        val out = LinkedHashMap<String, String>()
        for (authIdx in intArrayOf(7, 6)) {                 // teeEnforced, then softwareEnforced
            val auth = elems.getOrNull(authIdx) ?: continue
            for (tlv in Der.tlvList(auth.value)) {
                for ((name, tag) in ATTEST_ID) {
                    if (tlv.tag.contentEquals(tag) && name !in out) {
                        val (octet, _) = Der.readTlv(tlv.value, 0)   // EXPLICIT -> OCTET STRING
                        out[name] = String(octet.value, Charsets.US_ASCII)
                    }
                }
            }
        }
        return out
    }

    /**
     * The attested app identity (tag 709), or null when the certificate carries no
     * KeyDescription or no application id. Never throws: an unreadable value must
     * contribute nothing, per the fail-open rule.
     *
     * AttestationApplicationId ::= SEQUENCE {
     *     packageInfos      SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
     *     signatureDigests  SET OF OCTET STRING
     * }
     */
    fun attestedApp(cert: X509Certificate): AttestedApp? {
        val elems = runCatching { Der.sequenceElements(keyDescriptionDer(cert)) }.getOrNull()
            ?: return null
        // softwareEnforced (6) first: that is where the platform writes 709. Fall back
        // to teeEnforced (7) so an unusual KeyMint that promotes it is still read.
        for (authIdx in intArrayOf(6, 7)) {
            val auth = elems.getOrNull(authIdx) ?: continue
            for (tlv in Der.tlvList(auth.value)) {
                if (!tlv.tag.contentEquals(ATTEST_APP_ID_TAG)) continue
                val inner = runCatching {
                    val (octet, _) = Der.readTlv(tlv.value, 0)      // EXPLICIT -> OCTET STRING
                    Der.sequenceElements(octet.value)
                }.getOrNull() ?: return null
                val pkgs = runCatching {
                    Der.tlvList(inner[0].value).map { info ->
                        // info IS the AttestationPackageInfo SEQUENCE; its .value is
                        // already the contents, so split it directly rather than
                        // unwrapping another layer.
                        String(Der.tlvList(info.value)[0].value, Charsets.UTF_8)
                    }
                }.getOrDefault(emptyList())
                val digests = runCatching {
                    Der.tlvList(inner[1].value).map { Hex.encode(it.value) }
                }.getOrDefault(emptyList())
                if (pkgs.isEmpty() && digests.isEmpty()) return null
                return AttestedApp(pkgs, digests)
            }
        }
        return null
    }

    /** Platform tags from the leaf. Every field is null when absent — never throws. */
    fun attestedPlatform(cert: X509Certificate): AttestedPlatform {
        val elems = runCatching { Der.sequenceElements(keyDescriptionDer(cert)) }.getOrNull()
            ?: return AttestedPlatform(null, null, null, null)
        var os: Int? = null; var osp: Int? = null; var vp: Int? = null; var bp: Int? = null
        // teeEnforced (7) first: these are hardware-asserted. Fall back to
        // softwareEnforced (6) for KeyMint versions that place them there.
        for (authIdx in intArrayOf(7, 6)) {
            val auth = elems.getOrNull(authIdx) ?: continue
            for (tlv in Der.tlvList(auth.value)) {
                val v = runCatching {
                    val (inner, _) = Der.readTlv(tlv.value, 0)   // EXPLICIT -> INTEGER
                    var acc = 0L
                    for (b in inner.value) acc = (acc shl 8) or (b.toLong() and 0xff)
                    acc.toInt()
                }.getOrNull() ?: continue
                when {
                    tlv.tag.contentEquals(OS_VERSION_TAG)     && os  == null -> os  = v
                    tlv.tag.contentEquals(OS_PATCH_LEVEL_TAG) && osp == null -> osp = v
                    tlv.tag.contentEquals(VENDOR_PATCH_TAG)   && vp  == null -> vp  = v
                    tlv.tag.contentEquals(BOOT_PATCH_TAG)     && bp  == null -> bp  = v
                }
            }
        }
        return AttestedPlatform(os, osp, vp, bp)
    }
}
