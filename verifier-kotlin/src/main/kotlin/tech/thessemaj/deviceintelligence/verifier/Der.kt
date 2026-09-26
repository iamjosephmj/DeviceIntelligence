package tech.thessemaj.deviceintelligence.verifier

/**
 * A minimal DER TLV reader — just enough to walk the Android Key Attestation
 * extension (KeyDescription) by hand, with no ASN.1 library. Direct port of the
 * helpers in tools/server/verify_token.py (_der_read_len / _read_tlv / _tlv_list).
 *
 * Only structural decoding is done here (tags, lengths, raw values); semantic
 * interpretation lives in [Attestation].
 */
internal object Der {

    /** One decoded TLV: its full tag bytes and its raw value bytes. */
    data class Tlv(val tag: ByteArray, val value: ByteArray)

    /** Read a DER length at [i]; returns (length, nextIndex). */
    private fun readLen(b: ByteArray, i0: Int): Pair<Int, Int> {
        var i = i0
        val n = b[i].toInt() and 0xff; i++
        if (n < 0x80) return n to i
        val k = n and 0x7f
        var v = 0
        var j = 0
        while (j < k) { v = (v shl 8) or (b[i].toInt() and 0xff); i++; j++ }
        return v to i
    }

    /** Read one TLV at [i0] (handles multi-byte high-tag numbers). Returns (tlv, nextIndex). */
    fun readTlv(b: ByteArray, i0: Int): Pair<Tlv, Int> {
        var i = i0
        val start = i
        val t = b[i].toInt() and 0xff; i++
        if ((t and 0x1f) == 0x1f) {                 // high-tag-number form
            while ((b[i].toInt() and 0x80) != 0) i++
            i++
        }
        val tag = b.copyOfRange(start, i)
        val (ln, afterLen) = readLen(b, i)
        i = afterLen
        val value = b.copyOfRange(i, i + ln)
        i += ln
        return Tlv(tag, value) to i
    }

    /** Split a SEQUENCE/SET value into its element TLVs, in order. */
    fun tlvList(seqValue: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var i = 0
        while (i < seqValue.size) {
            val (tlv, next) = readTlv(seqValue, i)
            out.add(tlv)
            i = next
        }
        return out
    }

    /** Unwrap one outer SEQUENCE and return its element TLVs. */
    fun sequenceElements(der: ByteArray): List<Tlv> {
        val (outer, _) = readTlv(der, 0)
        return tlvList(outer.value)
    }
}
