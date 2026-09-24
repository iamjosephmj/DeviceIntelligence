package tech.thessemaj.deviceintelligence.verifier

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * v2 ECIES token crypto — the backend (decrypt) side. Mirrors the native
 * dicore_token_encrypt (dicore/crypto/token_crypto.cpp):
 *
 *   token  = "2:" + hex(version(1)||epoch(1)||eph_pub(32)||nonce(12)||ct||tag(16))
 *   shared = X25519(server_priv, eph_pub)
 *   key    = HKDF-SHA256(ikm=shared, salt=nonce, info="intel-token-v2"||epoch, 32)
 *   plain  = AES-256-GCM-open(key, nonce, ct||tag, aad=version||epoch||eph_pub)
 *
 * The device holds only the server PUBLIC key (.deviceintelligence), so there is no extractable
 * transport secret. Unforgeability still rests on the inner hardware signature —
 * v2 only replaces the outer envelope. Zero runtime deps (all JDK crypto).
 */
internal object TokenCryptoV2 {
    private const val PREFIX = "2:"
    private val INFO_PREFIX = "intel-token-v2".toByteArray(Charsets.UTF_8)
    private const val HEADER = 1 + 1 + 32 + 12   // version+epoch+eph_pub+nonce
    private const val TAG = 16

    /** A v1 token is pure lowercase hex (no ':'); v2 carries the "2:" discriminator. */
    fun isV2(token: String): Boolean = token.startsWith(PREFIX)

    /** Decrypt a "2:" token with the server X25519 private key.
     *  Throws AEADBadTagException on tamper, IllegalArgumentException if malformed.
     *
     *  Typed as [PrivateKey], NOT XECPrivateKey: KeyAgreement.init() needs no more than
     *  this, and Android's Conscrypt returns an OpenSSLX25519PrivateKey that does NOT
     *  implement XECPrivateKey — so the narrower type made the backend library unusable
     *  from an on-device in-app backend or an instrumented test, for nothing. */
    fun decrypt(tokenV2: String, serverPriv: PrivateKey): ByteArray {
        require(tokenV2.startsWith(PREFIX)) { "not a v2 token" }
        val p = Hex.decode(tokenV2.substring(PREFIX.length))
        require(p.size >= HEADER + TAG) { "v2 token too short" }

        val version = p[0]
        val epoch = p[1]
        val ephPub = p.copyOfRange(2, 34)
        val nonce = p.copyOfRange(34, 46)
        val ctAndTag = p.copyOfRange(HEADER, p.size)   // JCE GCM wants ct||tag concatenated

        val shared = agree(serverPriv, ephPub)
        val key = Hkdf.sha256(shared, nonce, INFO_PREFIX + byteArrayOf(epoch), 32)

        val aad = ByteArray(34)
        aad[0] = version
        aad[1] = epoch
        System.arraycopy(ephPub, 0, aad, 2, 32)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG * 8, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ctAndTag)
    }

    /**
     * A private key holding the raw 32-byte X25519 scalar, for platforms with no
     * `XDH` provider. Not a JCE key in any real sense — [agree] recognises it by type
     * and never hands it to a provider.
     */
    private class RawX25519PrivateKey(val scalar: ByteArray) : PrivateKey {
        init { require(scalar.size == 32) { "X25519 scalar must be 32 bytes, was ${scalar.size}" } }
        override fun getAlgorithm() = "XDH"
        override fun getFormat(): String? = null      // not extractable via getEncoded
        override fun getEncoded(): ByteArray? = null
    }

    /** Wrap a raw 32-byte X25519 scalar as a [PrivateKey] usable by [decrypt]. */
    fun rawX25519PrivateKey(scalar: ByteArray): PrivateKey = RawX25519PrivateKey(scalar.copyOf())

    /**
     * PKCS#8 for X25519 is fixed-shape:
     *   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.110 }, OCTET STRING { OCTET STRING(32) } }
     * so the scalar is simply the last 32 bytes. Used only on the no-XDH path, where
     * KeyFactory cannot parse it for us.
     */
    internal fun scalarFromPkcs8(der: ByteArray): ByteArray {
        require(der.size >= 32) { "PKCS#8 X25519 key too short: ${der.size} bytes" }
        return der.copyOfRange(der.size - 32, der.size)
    }

    /**
     * ECDH. Prefers the platform provider so a backend JVM behaves exactly as before;
     * falls back to the vendored [X25519] when no `XDH` provider exists (Android below
     * API 33 — our floor is API 28).
     */
    private fun agree(priv: PrivateKey, peerPubLe: ByteArray): ByteArray {
        if (priv is RawX25519PrivateKey) return X25519.scalarmult(priv.scalar, peerPubLe)
        return try {
            val ka = KeyAgreement.getInstance("XDH")
            ka.init(priv)
            ka.doPhase(publicFromLe(peerPubLe), true)
            ka.generateSecret()
        } catch (e: java.security.NoSuchAlgorithmException) {
            // No provider. The scalar is only reachable if the key is extractable;
            // a hardware-backed or opaque key cannot use this path, and rethrowing
            // beats silently producing a wrong secret.
            val enc = priv.encoded ?: throw e
            X25519.scalarmult(scalarFromPkcs8(enc), peerPubLe)
        }
    }

    /**
     * X25519 public key from a 32-byte little-endian u-coordinate (RFC 7748 §5),
     * built as an X.509 SubjectPublicKeyInfo.
     *
     * Deliberately NOT via XECPublicKeySpec: Android's Conscrypt rejects
     * java.security.spec.XECPublicKeySpec outright (it wants its own class), with the
     * self-contradicting message "Must use XECPublicKeySpec, X509EncodedKeySpec or Raw
     * EncodedKeySpec; was java.security.spec.XECPublicKeySpec". X509EncodedKeySpec
     * works on both the JVM and Android, so the backend library stays usable from an
     * in-app backend and from instrumented tests.
     *
     * SPKI prefix: SEQUENCE { SEQUENCE { OID 1.3.101.110 (id-X25519) }, BIT STRING }.
     * The u-coordinate goes in little-endian, exactly as it arrives on the wire.
     */
    private fun publicFromLe(le: ByteArray): PublicKey {
        require(le.size == 32) { "X25519 u-coordinate must be 32 bytes, was ${le.size}" }
        val u = le.copyOf()
        u[31] = (u[31].toInt() and 0x7f).toByte()   // clear the ignored high bit (RFC 7748)
        val der = SPKI_X25519_PREFIX + u
        return KeyFactory.getInstance("XDH").generatePublic(X509EncodedKeySpec(der))
    }

    private val SPKI_X25519_PREFIX = byteArrayOf(
        0x30, 0x2a,                                      // SEQUENCE (42 bytes)
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,        //   SEQUENCE { OID 1.3.101.110 }
        0x03, 0x21, 0x00,                                //   BIT STRING (33 bytes, 0 unused)
    )
}
