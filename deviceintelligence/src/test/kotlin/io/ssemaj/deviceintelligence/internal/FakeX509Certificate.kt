package io.ssemaj.deviceintelligence.internal

import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date

/**
 * Minimal in-memory [X509Certificate] for ChainValidator unit tests.
 *
 * Implements only the methods [ChainValidator] actually calls; every
 * other abstract method delegates to `error()` so accidental use in
 * unrelated code paths fails loudly rather than returning a misleading
 * default.
 *
 * The `verifyResult` lambda lets tests inject signature-verify
 * outcomes without setting up a real EC keypair / signature.
 *
 * Real device tests (running on instrumented Android) still exercise
 * the live `keystore.getCertificateChain()` -> `chain[i].verify(...)`
 * path against actual TEE-issued certs; this fake exists only to
 * cover the validator's branch coverage in pure JVM.
 */
internal class FakeX509Certificate(
    private val notBefore: Date,
    private val notAfter: Date,
    private val publicKey: PublicKey,
    private val encoded: ByteArray,
    private val serial: BigInteger,
    private val verifyResult: (PublicKey) -> Unit = { /* default: ok */ },
) : X509Certificate() {

    override fun getNotBefore(): Date = notBefore
    override fun getNotAfter(): Date = notAfter
    override fun getPublicKey(): PublicKey = publicKey
    override fun getEncoded(): ByteArray = encoded
    override fun getSerialNumber(): BigInteger = serial

    override fun verify(key: PublicKey) {
        verifyResult(key)
    }

    override fun verify(key: PublicKey, sigProvider: String?) {
        verifyResult(key)
    }

    // ---- abstract members we don't exercise: blow up loudly --------------

    override fun toString(): String = "FakeX509Certificate(serial=$serial)"
    override fun getVersion(): Int = error("not used")
    @Suppress("DEPRECATION")
    override fun getIssuerDN(): java.security.Principal = error("not used")
    @Suppress("DEPRECATION")
    override fun getSubjectDN(): java.security.Principal = error("not used")
    override fun getTBSCertificate(): ByteArray = error("not used")
    override fun getSignature(): ByteArray = error("not used")
    override fun getSigAlgName(): String = error("not used")
    override fun getSigAlgOID(): String = error("not used")
    override fun getSigAlgParams(): ByteArray? = null
    override fun getIssuerUniqueID(): BooleanArray? = null
    override fun getSubjectUniqueID(): BooleanArray? = null
    override fun getKeyUsage(): BooleanArray? = null
    override fun getBasicConstraints(): Int = -1
    override fun checkValidity() { /* no-op */ }
    override fun checkValidity(date: Date?) { /* no-op */ }
    override fun hasUnsupportedCriticalExtension(): Boolean = false
    override fun getCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
    override fun getNonCriticalExtensionOIDs(): MutableSet<String> = mutableSetOf()
    override fun getExtensionValue(oid: String?): ByteArray? = null
}

/**
 * Minimal in-memory PublicKey for tests; we only ever read .encoded
 * via [PublicKey] interface.
 */
internal class FakePublicKey(private val encoded: ByteArray) : PublicKey {
    override fun getAlgorithm(): String = "EC"
    override fun getFormat(): String = "X.509"
    override fun getEncoded(): ByteArray = encoded
}
