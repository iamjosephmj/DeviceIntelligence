package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyFactory
import java.security.interfaces.XECPrivateKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import javax.crypto.AEADBadTagException

/**
 * Deep tests for the v2 ECIES backend decrypt. The primary vector was produced by
 * the NATIVE dicore_token_encrypt with a fixed server keypair/ephemeral/nonce, so the
 * happy path proves native-encrypt / JVM-decrypt interop. The rest is a malformed +
 * per-region-tamper matrix: every corruption must throw (never return plaintext).
 */
class TokenCryptoV2Test {
    private val serverPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    private val token =
        "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d101112131415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b"
    // Same fixed key/ephemeral/nonce but EMPTY plaintext -> 62-byte payload (ct length 0).
    private val emptyToken =
        "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d101112131415161718191a1b9a7f7296f43354e241400ee7b8946c46"
    private val expectedPlain = "signed_content\n--BINDING\nSIG...\nCERT..."

    private fun priv(hex: String): XECPrivateKey =
        KeyFactory.getInstance("XDH")
            .generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, Hex.decode(hex))) as XECPrivateKey
    private fun serverPriv() = priv(serverPrivHex)

    // Flip one hex nibble at char index [i] within the payload (after the "2:").
    private fun flipAt(tok: String, i: Int): String {
        val body = tok.substring(2).toCharArray()
        body[i] = if (body[i] == '0') '1' else '0'
        return "2:" + String(body)
    }

    // ---------------- happy path (native interop) ----------------
    @Test fun decrypts_native_v2_token() {
        assertEquals(expectedPlain, String(TokenCryptoV2.decrypt(token, serverPriv()), Charsets.UTF_8))
    }

    @Test fun decrypts_empty_ciphertext_token() {
        assertEquals(0, TokenCryptoV2.decrypt(emptyToken, serverPriv()).size)
    }

    // ---------------- per-region tamper matrix (all -> AEADBadTagException) ----------------
    // Payload hex layout after "2:": version[0..1] epoch[2..3] ephPub[4..67]
    // nonce[68..91] ct[92..] tag[last 32].
    @Test fun tamper_version_fails() { assertBadTag(flipAt(token, 0)) }
    @Test fun tamper_epoch_fails() { assertBadTag(flipAt(token, 2)) }
    @Test fun tamper_ephPub_fails() { assertBadTag(flipAt(token, 10)) }
    @Test fun tamper_nonce_fails() { assertBadTag(flipAt(token, 70)) }
    @Test fun tamper_ciphertext_fails() { assertBadTag(flipAt(token, 92)) }
    @Test fun tamper_tag_fails() { assertBadTag(flipAt(token, token.length - 3)) }
    @Test fun tamper_empty_token_tag_fails() { assertBadTag(flipAt(emptyToken, emptyToken.length - 3)) }

    private fun assertBadTag(bad: String) {
        assertThrows(AEADBadTagException::class.java) { TokenCryptoV2.decrypt(bad, serverPriv()) }
    }

    // ---------------- wrong key ----------------
    @Test fun wrong_server_key_fails() {
        val other = priv("0202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21")
        assertThrows(AEADBadTagException::class.java) { TokenCryptoV2.decrypt(token, other) }
    }

    // ---------------- degenerate ephemeral point ----------------
    @Test fun all_zero_ephemeral_point_throws() {
        // Replace the 32-byte eph_pub (hex chars 4..67) with all zeros: a low-order
        // point. XDH rejects it (contributory behaviour) -> some exception, never plaintext.
        val body = token.substring(2).toCharArray()
        for (i in 4..67) body[i] = '0'
        val bad = "2:" + String(body)
        var threw = false
        try { TokenCryptoV2.decrypt(bad, serverPriv()) } catch (_: Throwable) { threw = true }
        assertTrue("all-zero ephemeral point must not decrypt", threw)
    }

    // ---------------- malformed envelope ----------------
    @Test fun rejects_missing_prefix() {
        assertThrows(IllegalArgumentException::class.java) { TokenCryptoV2.decrypt("deadbeefcafe", serverPriv()) }
    }
    @Test fun rejects_too_short_payload() {
        assertThrows(IllegalArgumentException::class.java) { TokenCryptoV2.decrypt("2:0203", serverPriv()) }
    }
    @Test fun rejects_odd_length_hex() {
        assertThrows(IllegalArgumentException::class.java) { TokenCryptoV2.decrypt("2:abc", serverPriv()) }
    }
    @Test fun rejects_non_hex_chars() {
        assertThrows(IllegalArgumentException::class.java) { TokenCryptoV2.decrypt("2:zzzz", serverPriv()) }
    }

    // ---------------- discriminator ----------------
    @Test fun isV2_discriminates_from_v1() {
        assertTrue(TokenCryptoV2.isV2(token))
        assertTrue(TokenCryptoV2.isV2(emptyToken))
        assertFalse(TokenCryptoV2.isV2("deadbeefcafe"))   // v1 = pure hex, no prefix
        assertFalse(TokenCryptoV2.isV2(""))
        assertFalse(TokenCryptoV2.isV2("2"))
    }
}
