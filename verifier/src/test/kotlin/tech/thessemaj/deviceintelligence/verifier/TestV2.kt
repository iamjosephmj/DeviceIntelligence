package tech.thessemaj.deviceintelligence.verifier

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Device-side mirror of [TokenCryptoV2], for tests only — the production verifier
 * only ever decrypts. Must stay byte-compatible with native dicore_token_encrypt:
 *
 *   "2:" + hex(version(1) || epoch(1) || ephPub(32) || nonce(12) || ct || tag(16))
 */
object TestV2 {

    fun serverKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("XDH")
        kpg.initialize(NamedParameterSpec("X25519"))
        return kpg.generateKeyPair()
    }

    fun encryptForTest(plain: String, serverPub: PublicKey, epoch: Int = 0): String {
        val eph = serverKeyPair()

        val ka = KeyAgreement.getInstance("XDH")
        ka.init(eph.private)
        ka.doPhase(serverPub, true)
        val shared = ka.generateSecret()

        val ephRaw = eph.public.encoded.let { it.copyOfRange(it.size - 32, it.size) }
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val key = Hkdf.sha256(shared, nonce,
            "intel-token-v2".toByteArray(Charsets.UTF_8) + byteArrayOf(epoch.toByte()), 32)

        val aad = ByteArray(34)
        aad[0] = 2
        aad[1] = epoch.toByte()
        System.arraycopy(ephRaw, 0, aad, 2, 32)

        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        val ctAndTag = c.doFinal(plain.toByteArray(Charsets.UTF_8))

        return "2:" + Hex.encode(byteArrayOf(2, epoch.toByte()) + ephRaw + nonce + ctAndTag)
    }
}
