package tech.thessemaj.deviceintelligence.verifier

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869), Extract-then-Expand, via HmacSHA256. Byte-for-byte
 * equivalent to the native dicore/crypto/hkdf.cpp (empty salt -> 32 zero bytes;
 * T(i) = HMAC(PRK, T(i-1)||info||i)). Extracted from TokenCryptoV2 so it can be
 * KAT'd directly against the RFC vectors.
 */
internal object Hkdf {
    fun sha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        require(outLen in 0..(255 * 32)) { "HKDF outLen out of range: $outLen" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)                    // Extract

        mac.init(SecretKeySpec(prk, "HmacSHA256"))    // Expand
        val out = ByteArray(outLen)
        var t = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < outLen) {
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()                          // resets the Mac to its keyed state
            val take = minOf(t.size, outLen - pos)
            System.arraycopy(t, 0, out, pos, take)
            pos += take
            counter++
        }
        return out
    }
}
