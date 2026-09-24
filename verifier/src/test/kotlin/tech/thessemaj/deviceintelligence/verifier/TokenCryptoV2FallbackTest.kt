package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The no-XDH-provider path. Android's Conscrypt has no `XDH` provider below API 33,
 * so a verifier embedded in an app at our API 28 floor must decrypt without JCE.
 *
 * Both tests decrypt the SAME native-produced token as [TokenCryptoV2Test], so the
 * fallback is pinned to the native encryptor, not merely to itself.
 */
class TokenCryptoV2FallbackTest {
    private val serverPrivHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    private val token =
        "2:0203493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d101112131415161718191a1bf5fea180751d9d9068b0634b833499c54b955d2f849d9a3520574a600d852a2ff5909230650def8d9ce6fbe5c5f191285ba2c66e12a44b"
    private val expectedPlain = "signed_content\n--BINDING\nSIG...\nCERT..."

    /** PKCS#8 for X25519: SEQUENCE { 0, AlgId(1.3.101.110), OCTET STRING { OCTET STRING(32) } }. */
    private fun pkcs8(scalarHex: String) =
        Hex.decode("302e020100300506032b656e04220420" + scalarHex)

    @Test
    fun `raw scalar key decrypts a native token without any JCE provider`() {
        val priv = TokenCryptoV2.rawX25519PrivateKey(Hex.decode(serverPrivHex))
        assertEquals(expectedPlain, String(TokenCryptoV2.decrypt(token, priv), Charsets.UTF_8))
    }

    /** The public entry point the in-app backend uses to load its server half. */
    @Test
    fun `ServerKey parses PKCS8 and decrypts`() {
        val priv = ServerKey.fromPkcs8(pkcs8(serverPrivHex))
        assertEquals(expectedPlain, String(TokenCryptoV2.decrypt(token, priv), Charsets.UTF_8))
    }
}
