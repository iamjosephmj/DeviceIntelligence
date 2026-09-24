package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * RFC 7748 known-answer tests for the pure-Kotlin X25519 fallback.
 *
 * Same vectors the native side asserts in
 * deviceintelligence/src/main/cpp/test/crypto/test_x25519.cpp, so the two implementations are
 * pinned to one another through the spec rather than through each other.
 */
class X25519Test {

    /** RFC 7748 section 5.2, first scalarmult vector. */
    @Test
    fun `scalarmult matches RFC 7748 vector 1`() {
        val k = Hex.decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val u = Hex.decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        assertEquals(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            Hex.encode(X25519.scalarmult(k, u)),
        )
    }

    /** RFC 7748 section 5.2, second scalarmult vector. */
    @Test
    fun `scalarmult matches RFC 7748 vector 2`() {
        val k = Hex.decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        val u = Hex.decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        assertEquals(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            Hex.encode(X25519.scalarmult(k, u)),
        )
    }

    /** RFC 7748 section 6.1: both sides of an ECDH agree on one secret. */
    @Test
    fun `diffie hellman agrees on the shared secret`() {
        val aPriv = Hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bPriv = Hex.decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

        val aPub = X25519.scalarmultBase(aPriv)
        val bPub = X25519.scalarmultBase(bPriv)

        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Hex.encode(aPub))
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Hex.encode(bPub))

        val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        assertEquals(shared, Hex.encode(X25519.scalarmult(aPriv, bPub)))
        assertEquals(shared, Hex.encode(X25519.scalarmult(bPriv, aPub)))
    }
}
