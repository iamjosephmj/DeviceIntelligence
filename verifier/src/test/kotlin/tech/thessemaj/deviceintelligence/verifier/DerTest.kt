package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

/** Unit tests for the minimal DER TLV reader (short/long/high-tag forms). */
class DerTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test fun reads_short_form_tlv() {
        val (tlv, next) = Der.readTlv(bytes(0x02, 0x01, 0x05), 0)   // INTEGER 5
        assertArrayEquals(bytes(0x02), tlv.tag)
        assertArrayEquals(bytes(0x05), tlv.value)
        assertEquals(3, next)
    }

    @Test fun reads_long_form_length() {
        // OCTET STRING, 0x81 => 1 length byte = 0x80 (128) content bytes.
        val body = ByteArray(128) { 0x41 }
        val der = bytes(0x04, 0x81, 0x80) + body
        val (tlv, next) = Der.readTlv(der, 0)
        assertArrayEquals(bytes(0x04), tlv.tag)
        assertEquals(128, tlv.value.size)
        assertEquals(3 + 128, next)
    }

    @Test fun reads_two_byte_long_form_length() {
        val body = ByteArray(300) { 0x42 }
        val der = bytes(0x04, 0x82, 0x01, 0x2C) + body           // 0x012C = 300
        val (tlv, _) = Der.readTlv(der, 0)
        assertEquals(300, tlv.value.size)
    }

    @Test fun reads_high_tag_number_form() {
        // tag low 5 bits = 0x1f -> multi-byte tag: 0x1f 0x81 0x00, then len 1, value AA.
        val (tlv, next) = Der.readTlv(bytes(0x1f, 0x81, 0x00, 0x01, 0xAA), 0)
        assertArrayEquals(bytes(0x1f, 0x81, 0x00), tlv.tag)
        assertArrayEquals(bytes(0xAA), tlv.value)
        assertEquals(5, next)
    }

    @Test fun sequence_elements_splits_in_order() {
        // SEQUENCE { INTEGER 5, INTEGER 7 }
        val der = bytes(0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07)
        val els = Der.sequenceElements(der)
        assertEquals(2, els.size)
        assertArrayEquals(bytes(0x05), els[0].value)
        assertArrayEquals(bytes(0x07), els[1].value)
    }

    @Test fun tlv_list_walks_a_set_value() {
        // value of a SET: two OCTET STRINGs
        val v = bytes(0x04, 0x02, 0xDE, 0xAD, 0x04, 0x01, 0xBE)
        val els = Der.tlvList(v)
        assertEquals(2, els.size)
        assertArrayEquals(bytes(0xDE, 0xAD), els[0].value)
        assertArrayEquals(bytes(0xBE), els[1].value)
    }
}
