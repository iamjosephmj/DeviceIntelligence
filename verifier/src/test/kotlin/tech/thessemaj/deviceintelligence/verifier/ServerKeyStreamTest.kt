package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * The verifier loads the server key itself, so no caller ever touches KeyFactory.
 *
 * WHY this overload exists: `verifyScan(.., serverPriv: PrivateKey, ..)` forces the
 * CALLER to construct the key, and on Android below API 33 that construction throws
 * (`KeyFactory.getInstance("XDH")` — no Conscrypt provider). The library's fallback
 * could never run, because you cannot reach it without already holding a key you
 * could not build. Taking the key MATERIAL moves construction inside, where the
 * fallback lives, and makes the Android 9 trap unreachable rather than merely
 * documented.
 */
class ServerKeyStreamTest {

    private val kp = TestV2.serverKeyPair()

    /** PKCS#8 for X25519 is fixed-shape; the scalar is the last 32 bytes. */
    private fun pemOf(pkcs8: ByteArray): String =
        "-----BEGIN PRIVATE KEY-----\n" +
            java.util.Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(pkcs8) +
            "\n-----END PRIVATE KEY-----\n"

    private fun scanJson(sessionId: String) =
        """{"schemaVersion":4,"type":"scan","sessionId":"$sessionId","name":"checkout",""" +
        """"ts":1,"bootstrap":false,""" +
        """"app":{"package":"com.example.app","signer":"${"aa".repeat(32)}"},""" +
        """"device":{"api":28,"abi":"arm64-v8a","model":"SM-T515"},"signals":[]}"""

    @Test
    fun `an InputStream of PEM opens the same token as a PrivateKey`() {
        val json = scanJson("s1")
        val token = TestV2.encryptForTest("$json\n--BINDING\nSIG\u001Fdead", kp.public)
        val pem = pemOf(kp.private.encoded)

        val viaKey = ScanVerifier().verifyScan(token, "s1", kp.private)
        val viaPem = ScanVerifier().verifyScan(token, "s1", ByteArrayInputStream(pem.toByteArray()))

        // Same envelope, so the same verdict and the same reason - the key route
        // must not change anything downstream of decryption.
        assertEquals(viaKey.reason, viaPem.reason)
        assertEquals(viaKey.ok, viaPem.ok)
        assertTrue("the envelope must actually open", viaPem.checks.first { it.name == "envelope opens" }.ok)
    }

    @Test
    fun `the parsed key is cached, so repeated scans do not re-parse`() {
        val sv = ScanVerifier()
        val pem = pemOf(kp.private.encoded).toByteArray()
        val a = sv.serverKeyFrom(ByteArrayInputStream(pem))
        val b = sv.serverKeyFrom(ByteArrayInputStream(pem))
        assertSame("identical key material must yield the identical parsed key", a, b)
    }
}
