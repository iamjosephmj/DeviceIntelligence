package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/** Direct RFC 5869 KAT for the JVM HKDF (the native side is covered by test_hkdf.cpp;
 *  this proves the Kotlin implementation independently, not just via token interop). */
class HkdfTest {
    private fun ikm22() = Hex.decode("0b".repeat(22))

    @Test fun rfc5869_case1_with_salt_and_info() {
        val okm = Hkdf.sha256(
            ikm22(),
            Hex.decode("000102030405060708090a0b0c"),
            Hex.decode("f0f1f2f3f4f5f6f7f8f9"),
            42,
        )
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            Hex.encode(okm),
        )
    }

    @Test fun rfc5869_case3_empty_salt_and_info() {
        val okm = Hkdf.sha256(ikm22(), ByteArray(0), ByteArray(0), 42)
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            Hex.encode(okm),
        )
    }

    @Test fun rejects_output_over_255_blocks() {
        assertThrows(IllegalArgumentException::class.java) {
            Hkdf.sha256(byteArrayOf(1), ByteArray(0), ByteArray(0), 255 * 32 + 1)
        }
    }

    @Test fun token_derivation_shape_is_32_bytes() {
        val key = Hkdf.sha256(
            Hex.decode("00".repeat(32)), Hex.decode("10".repeat(12)),
            "intel-token-v2".toByteArray(Charsets.UTF_8) + byteArrayOf(3), 32,
        )
        assertEquals(32, key.size)
    }
}
