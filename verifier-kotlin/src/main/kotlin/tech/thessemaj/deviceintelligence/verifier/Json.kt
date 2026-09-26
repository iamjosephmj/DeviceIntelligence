package tech.thessemaj.deviceintelligence.verifier

/**
 * A tiny, dependency-free JSON reader — enough to parse the token's compact
 * `signed_content` and the bundled signal registry. Returns Kotlin values:
 * `Map<String, Any?>`, `List<Any?>`, `String`, `Long`, `Double`, `Boolean`, `null`.
 *
 * Deliberately minimal (no pretty-printing, no streaming); the documents it reads
 * are small and machine-generated. Throws [IllegalArgumentException] on malformed
 * input.
 */
internal object Json {

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.readValue()
        p.skipWs()
        require(p.atEnd()) { "trailing data at ${p.pos}" }
        return v
    }

    @Suppress("UNCHECKED_CAST")
    fun parseObject(text: String): Map<String, Any?> =
        parse(text) as? Map<String, Any?> ?: throw IllegalArgumentException("not a JSON object")

    private class Parser(val s: String) {
        var pos = 0
        fun atEnd() = pos >= s.length
        fun skipWs() { while (pos < s.length && s[pos].isWhitespace()) pos++ }

        fun readValue(): Any? {
            skipWs()
            require(!atEnd()) { "unexpected end" }
            return when (s[pos]) {
                '{' -> readObject()
                '[' -> readArray()
                '"' -> readString()
                't', 'f' -> readBool()
                'n' -> readNull()
                else -> readNumber()
            }
        }

        fun readObject(): Map<String, Any?> {
            val out = LinkedHashMap<String, Any?>()
            expect('{'); skipWs()
            if (peek() == '}') { pos++; return out }
            while (true) {
                skipWs()
                val key = readString()
                skipWs(); expect(':')
                out[key] = readValue()
                skipWs()
                when (val c = next()) {
                    ',' -> continue
                    '}' -> break
                    else -> throw IllegalArgumentException("expected , or } but got '$c'")
                }
            }
            return out
        }

        fun readArray(): List<Any?> {
            val out = ArrayList<Any?>()
            expect('['); skipWs()
            if (peek() == ']') { pos++; return out }
            while (true) {
                out.add(readValue())
                skipWs()
                when (val c = next()) {
                    ',' -> continue
                    ']' -> break
                    else -> throw IllegalArgumentException("expected , or ] but got '$c'")
                }
            }
            return out
        }

        fun readString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                require(!atEnd()) { "unterminated string" }
                val c = s[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        val e = s[pos++]
                        when (e) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'n' -> sb.append('\n'); 't' -> sb.append('\t'); 'r' -> sb.append('\r')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C')
                            'u' -> { sb.append(s.substring(pos, pos + 4).toInt(16).toChar()); pos += 4 }
                            else -> throw IllegalArgumentException("bad escape \\$e")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        fun readNumber(): Any {
            val start = pos
            while (pos < s.length && (s[pos].isDigit() || s[pos] in "-+.eE")) pos++
            val tok = s.substring(start, pos)
            require(tok.isNotEmpty()) { "invalid number at $start" }
            return if (tok.any { it == '.' || it == 'e' || it == 'E' }) tok.toDouble() else tok.toLong()
        }

        fun readBool(): Boolean =
            if (s.startsWith("true", pos)) { pos += 4; true }
            else if (s.startsWith("false", pos)) { pos += 5; false }
            else throw IllegalArgumentException("invalid literal at $pos")

        fun readNull(): Any? {
            require(s.startsWith("null", pos)) { "invalid literal at $pos" }
            pos += 4; return null
        }

        private fun peek(): Char { skipWs(); return s[pos] }
        private fun next(): Char { skipWs(); return s[pos++] }
        private fun expect(c: Char) {
            skipWs()
            require(!atEnd() && s[pos] == c) { "expected '$c' at $pos" }
            pos++
        }
    }
}
