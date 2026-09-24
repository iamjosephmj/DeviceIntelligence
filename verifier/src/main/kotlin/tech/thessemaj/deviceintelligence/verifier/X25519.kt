package tech.thessemaj.deviceintelligence.verifier

/**
 * X25519 (Curve25519 scalar multiplication), pure Kotlin.
 *
 * VENDORED from TweetNaCl v20140427 (Bernstein, van Gastel, Janssen, Lange,
 * Schwabe, Smetsers), dedicated by its authors to the PUBLIC DOMAIN
 * (https://tweetnacl.cr.yp.to/). This is a line-for-line port of the same
 * reference the device side already carries at
 * `deviceintelligence/src/main/cpp/dicore/crypto/x25519.cpp`, so both halves of the v2
 * token protocol trace to one implementation. The field arithmetic is unchanged
 * from the reference and is constant-time by construction.
 *
 * WHY this exists at all, given the JDK ships XDH since Java 11: Android's
 * Conscrypt only exposes an `XDH` provider on recent releases, and our floor is
 * API 28 (Android 9). `KeyFactory.getInstance("XDH")` throws
 * NoSuchAlgorithmException there, which took out the whole scan path when the
 * verifier runs as an in-app backend. [TokenCryptoV2] therefore prefers the
 * platform provider and falls back here only when it is absent — a backend JVM
 * keeps using Conscrypt/SunEC exactly as before.
 */
internal object X25519 {

    /** RFC 7748 base point u = 9. */
    private val BASE = ByteArray(32).also { it[0] = 9 }

    /** k * u, both 32-byte little-endian. The scalar is clamped per RFC 7748. */
    fun scalarmult(scalar: ByteArray, point: ByteArray): ByteArray {
        require(scalar.size == 32) { "scalar must be 32 bytes, was ${scalar.size}" }
        require(point.size == 32) { "u-coordinate must be 32 bytes, was ${point.size}" }
        return crypto(scalar, point)
    }

    /** k * 9 — the public half of a private scalar. */
    fun scalarmultBase(scalar: ByteArray): ByteArray = scalarmult(scalar, BASE)

    // ---- field arithmetic over GF(2^255-19), 16 limbs of 16 bits ----

    private fun gf() = LongArray(16)

    private fun car25519(o: LongArray) {
        for (i in 0 until 16) {
            o[i] += (1L shl 16)
            val c = o[i] shr 16
            o[(i + 1) * (if (i < 15) 1 else 0)] += c - 1 + 37 * (c - 1) * (if (i == 15) 1 else 0)
            o[i] -= c shl 16
        }
    }

    /** Constant-time conditional swap of p and q on b. */
    private fun sel25519(p: LongArray, q: LongArray, b: Int) {
        val c = (b.toLong() - 1).inv()
        for (i in 0 until 16) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack25519(o: ByteArray, n: LongArray) {
        val t = gf()
        val m = gf()
        for (i in 0 until 16) t[i] = n[i]
        car25519(t); car25519(t); car25519(t)
        for (j in 0 until 2) {
            m[0] = t[0] - 0xffed
            for (i in 1 until 15) {
                m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
                m[i - 1] = m[i - 1] and 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
            val b = ((m[15] shr 16) and 1).toInt()
            m[14] = m[14] and 0xffff
            sel25519(t, m, 1 - b)
        }
        for (i in 0 until 16) {
            o[2 * i] = (t[i] and 0xff).toByte()
            o[2 * i + 1] = (t[i] shr 8).toByte()
        }
    }

    private fun unpack25519(o: LongArray, n: ByteArray) {
        for (i in 0 until 16) {
            o[i] = (n[2 * i].toLong() and 0xff) + ((n[2 * i + 1].toLong() and 0xff) shl 8)
        }
        o[15] = o[15] and 0x7fff
    }

    private fun add(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] + b[i]
    }

    private fun sub(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) o[i] = a[i] - b[i]
    }

    private fun mul(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0 until 16) for (j in 0 until 16) t[i + j] += a[i] * b[j]
        for (i in 0 until 15) t[i] += 38 * t[i + 16]
        for (i in 0 until 16) o[i] = t[i]
        car25519(o); car25519(o)
    }

    private fun sq(o: LongArray, a: LongArray) = mul(o, a, a)

    private fun inv25519(o: LongArray, i: LongArray) {
        val c = gf()
        for (a in 0 until 16) c[a] = i[a]
        for (a in 253 downTo 0) {
            sq(c, c)
            if (a != 2 && a != 4) mul(c, c, i)
        }
        for (a in 0 until 16) o[a] = c[a]
    }

    private val N121665 = gf().also { it[0] = 0xDB41; it[1] = 1 }

    private fun crypto(n: ByteArray, p: ByteArray): ByteArray {
        val z = ByteArray(32)
        for (i in 0 until 31) z[i] = n[i]
        z[31] = ((n[31].toInt() and 127) or 64).toByte()
        z[0] = (z[0].toInt() and 248).toByte()

        val x = gf(); unpack25519(x, p)
        val a = gf(); val b = gf(); val c = gf(); val d = gf(); val e = gf(); val f = gf()
        for (i in 0 until 16) b[i] = x[i]
        a[0] = 1; d[0] = 1

        for (i in 254 downTo 0) {
            val r = ((z[i shr 3].toInt() shr (i and 7)) and 1)
            sel25519(a, b, r)
            sel25519(c, d, r)
            add(e, a, c)
            sub(a, a, c)
            add(c, b, d)
            sub(b, b, d)
            sq(d, e)
            sq(f, a)
            mul(a, c, a)
            mul(c, b, e)
            add(e, a, c)
            sub(a, a, c)
            sq(b, a)
            sub(c, d, f)
            mul(a, c, N121665)
            add(a, a, d)
            mul(c, c, a)
            mul(a, d, f)
            mul(d, b, x)
            sq(b, e)
            sel25519(a, b, r)
            sel25519(c, d, r)
        }

        inv25519(c, c)
        mul(a, a, c)
        val q = ByteArray(32)
        pack25519(q, a)
        return q
    }
}
