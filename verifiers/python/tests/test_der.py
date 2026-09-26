"""The minimal DER TLV reader (Der.kt port) — short/long/high-tag forms."""
from deviceintelligence_verifier.der import read_tlv, tlv_list, sequence_elements


def test_reads_short_form_tlv():
    tlv, nxt = read_tlv(bytes([0x02, 0x01, 0x05]), 0)
    assert tlv.tag == bytes([0x02]) and tlv.value == bytes([0x05]) and nxt == 3


def test_reads_long_form_length():
    der = bytes([0x04, 0x81, 0x80]) + bytes(128)
    tlv, nxt = read_tlv(der, 0)
    assert tlv.tag == bytes([0x04]) and len(tlv.value) == 128 and nxt == 3 + 128


def test_reads_two_byte_long_form_length():
    der = bytes([0x04, 0x82, 0x01, 0x2C]) + bytes(300)
    tlv, _ = read_tlv(der, 0)
    assert len(tlv.value) == 300


def test_reads_high_tag_number_form():
    tlv, nxt = read_tlv(bytes([0x1F, 0x81, 0x00, 0x01, 0xAA]), 0)
    assert tlv.tag == bytes([0x1F, 0x81, 0x00]) and tlv.value == bytes([0xAA]) and nxt == 5


def test_sequence_elements_splits_in_order():
    els = sequence_elements(bytes([0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07]))
    assert [e.value for e in els] == [bytes([0x05]), bytes([0x07])]


def test_tlv_list_walks_a_set_value():
    els = tlv_list(bytes([0x04, 0x02, 0xDE, 0xAD, 0x04, 0x01, 0xBE]))
    assert els[0].value == bytes([0xDE, 0xAD]) and els[1].value == bytes([0xBE])
