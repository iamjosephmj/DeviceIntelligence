package io.ssemaj.deviceintelligence.internal

/**
 * Tiny DER encoder used only by the F14 unit tests.
 *
 * Produces just enough of the ASN.1 wire format to construct
 * representative `KeyDescription` extensions in-memory: SEQUENCE,
 * SET, INTEGER, ENUMERATED, OCTET STRING, BOOLEAN, plus
 * context-specific [N] EXPLICIT wrappers for both single-byte
 * (N <= 30) and multi-byte (N >= 31) tag forms.
 *
 * NOT a general-purpose DER encoder. Encodes lengths up to 0xFFFFFF
 * only; callers that build larger blobs are doing something wrong.
 */
internal object DerBuilder {

    private const val TAG_BOOLEAN = 0x01
    private const val TAG_INTEGER = 0x02
    private const val TAG_OCTET_STRING = 0x04
    private const val TAG_ENUMERATED = 0x0A
    private const val TAG_SEQUENCE = 0x30
    private const val TAG_SET = 0x31

    fun seq(vararg fields: ByteArray): ByteArray = wrapByte(TAG_SEQUENCE, concat(fields))
    fun set(vararg fields: ByteArray): ByteArray = wrapByte(TAG_SET, concat(fields))

    fun int(v: Int): ByteArray = wrapByte(TAG_INTEGER, encodeInt(v))
    fun enumerated(v: Int): ByteArray = wrapByte(TAG_ENUMERATED, encodeInt(v))
    fun bool(v: Boolean): ByteArray =
        wrapByte(TAG_BOOLEAN, byteArrayOf((if (v) 0xFF else 0x00).toByte()))

    fun octet(v: ByteArray): ByteArray = wrapByte(TAG_OCTET_STRING, v)

    /**
     * `[tagNum] EXPLICIT inner` — context-specific, constructed.
     * Handles both short-form (tagNum <= 30) and long-form (tagNum >= 31)
     * tag encodings, since the AuthorizationList uses both
     * (e.g. `[704]` for rootOfTrust requires the long form).
     */
    fun ctxExplicit(tagNum: Int, inner: ByteArray): ByteArray {
        val tagBytes = encodeContextConstructedTag(tagNum)
        val lenBytes = encodeLength(inner.size)
        val out = ByteArray(tagBytes.size + lenBytes.size + inner.size)
        var off = 0
        System.arraycopy(tagBytes, 0, out, off, tagBytes.size); off += tagBytes.size
        System.arraycopy(lenBytes, 0, out, off, lenBytes.size); off += lenBytes.size
        System.arraycopy(inner, 0, out, off, inner.size)
        return out
    }

    private fun wrapByte(tagByte: Int, value: ByteArray): ByteArray {
        val lenBytes = encodeLength(value.size)
        val out = ByteArray(1 + lenBytes.size + value.size)
        out[0] = tagByte.toByte()
        System.arraycopy(lenBytes, 0, out, 1, lenBytes.size)
        System.arraycopy(value, 0, out, 1 + lenBytes.size, value.size)
        return out
    }

    private fun encodeContextConstructedTag(tagNum: Int): ByteArray {
        // Class = 10 (context-specific), constructed = 1.
        val classConstructedBits = 0b1010_0000
        if (tagNum <= 30) {
            return byteArrayOf((classConstructedBits or tagNum).toByte())
        }
        // Long form: first byte has low 5 bits = 0x1F (escape).
        // Subsequent bytes carry 7 bits of tag number each, MSB
        // continuation flag, big-endian.
        val first = (classConstructedBits or 0x1F).toByte()
        val chunks = ArrayList<Int>(3)
        var n = tagNum
        while (n > 0) {
            chunks += n and 0x7F
            n = n ushr 7
        }
        chunks.reverse()
        val tail = ByteArray(chunks.size)
        for (i in chunks.indices) {
            val byte = chunks[i]
            tail[i] = if (i != chunks.lastIndex) {
                (byte or 0x80).toByte()
            } else {
                byte.toByte()
            }
        }
        return byteArrayOf(first) + tail
    }

    private fun encodeLength(len: Int): ByteArray {
        require(len >= 0) { "negative length: $len" }
        if (len < 0x80) return byteArrayOf(len.toByte())
        // Long form: first byte = 0x80 | numLengthBytes.
        return when {
            len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
            len < 0x10000 -> byteArrayOf(
                0x82.toByte(),
                (len ushr 8).toByte(),
                len.toByte(),
            )
            else -> byteArrayOf(
                0x83.toByte(),
                (len ushr 16).toByte(),
                (len ushr 8).toByte(),
                len.toByte(),
            )
        }
    }

    private fun encodeInt(v: Int): ByteArray {
        // Minimal big-endian two's-complement encoding.
        if (v == 0) return byteArrayOf(0x00)
        val tmp = java.math.BigInteger.valueOf(v.toLong()).toByteArray()
        return tmp
    }

    private fun concat(parts: Array<out ByteArray>): ByteArray {
        var total = 0
        for (p in parts) total += p.size
        val out = ByteArray(total)
        var off = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, off, p.size)
            off += p.size
        }
        return out
    }
}
