package tech.thessemaj.deviceintelligence.verifier

/**
 * JSON round-trip for [ScanSession].
 *
 * The verifier is stateless by construction: a bootstrap scan RETURNS the
 * attestation facts, and the caller stores them on its own session record and
 * hands them back on every later scan. That storage step is part of the contract,
 * so serialising the session belongs in the library rather than in each caller —
 * and a field that silently fails to round-trip is a fact quietly dropped from
 * every steady-state verdict, which is exactly the bug this being shared prevents.
 *
 * The wire form is the same shape the Python reference backend prints and reads
 * (`verify_token.py --scan … ` / `--session`), so a session established by one can
 * be adjudicated by the other.
 *
 * Zero dependencies, matching the rest of `:verifier`.
 */
object ScanSessionCodec {

    fun encode(s: ScanSession): String = buildString {
        append('{')
        str("attestedKey", s.attestedKey); comma()
        append("\"attestedApp\":")
        if (s.attestedApp == null) append("null") else {
            append("{\"packageNames\":"); arr(s.attestedApp.packageNames)
            append(",\"signatureDigests\":"); arr(s.attestedApp.signatureDigests)
            append('}')
        }
        comma(); str("assurance", s.assurance.name)
        comma(); str("bootState", s.bootState)
        comma(); bool("deviceLocked", s.deviceLocked)
        comma(); bool("chainTrusted", s.chainTrusted)
        comma(); bool("keyboxRevoked", s.keyboxRevoked)
        comma(); bool("crossLevelReuse", s.crossLevelReuse)
        comma(); bool("devicePropMismatch", s.devicePropMismatch)
        comma(); bool("bootStateSpoofer", s.bootStateSpoofer)
        comma(); bool("strongboxChainMissing", s.strongboxChainMissing)
        comma(); bool("softwareAttested", s.softwareAttested)
        comma(); num("osPatchLevel", s.osPatchLevel)
        comma(); num("vendorPatchLevel", s.vendorPatchLevel)
        comma(); num("bootPatchLevel", s.bootPatchLevel)
        comma(); append("\"fingerprint\":")
        if (s.fingerprint == null) append("null") else {
            append('{')
            strOrNull("id", s.fingerprint.id); comma()
            strOrNull("aid", s.fingerprint.aid); comma()
            strOrNull("securityLevel", s.fingerprint.securityLevel); comma()
            strOrNull("build", s.fingerprint.build); comma()
            strOrNull("kernel", s.fingerprint.kernel); comma()
            strOrNull("patch", s.fingerprint.patch); comma()
            strOrNull("installer", s.fingerprint.installer)
            append('}')
        }
        append('}')
    }

    /** @throws IllegalArgumentException if the document is not a session. */
    @Suppress("UNCHECKED_CAST")
    fun decode(json: String): ScanSession {
        val o = runCatching { Json.parseObject(json) }.getOrElse {
            throw IllegalArgumentException("not a JSON object: ${it.message}")
        }
        val key = o["attestedKey"] as? String
            ?: throw IllegalArgumentException("session has no attestedKey")

        val app = (o["attestedApp"] as? Map<String, Any?>)?.let {
            AttestedApp(
                packageNames = (it["packageNames"] as? List<Any?>).orEmpty().filterIsInstance<String>(),
                signatureDigests = (it["signatureDigests"] as? List<Any?>).orEmpty().filterIsInstance<String>(),
            )
        }
        val fp = (o["fingerprint"] as? Map<String, Any?>)?.let {
            DeviceFingerprint(
                id = it["id"] as? String,
                aid = it["aid"] as? String,
                securityLevel = it["securityLevel"] as? String,
                build = it["build"] as? String,
                kernel = it["kernel"] as? String,
                patch = it["patch"] as? String,
                installer = it["installer"] as? String,
            )
        }
        // An unknown or absent assurance grades DOWN, never up: absence of a level is
        // not evidence of hardware backing, and this decodes attacker-reachable input.
        val assurance = runCatching { Assurance.valueOf(o["assurance"] as String) }
            .getOrDefault(Assurance.SOFTWARE)

        return ScanSession(
            attestedKey = key,
            attestedApp = app,
            assurance = assurance,
            bootState = o["bootState"] as? String ?: "?",
            deviceLocked = o["deviceLocked"] == true,
            // These default to the SUSPICIOUS value when absent, the opposite of the
            // data class defaults: a truncated document must not read as a clean device.
            chainTrusted = o["chainTrusted"] == true,
            keyboxRevoked = o["keyboxRevoked"] != false,
            crossLevelReuse = o["crossLevelReuse"] != false,
            devicePropMismatch = o["devicePropMismatch"] != false,
            bootStateSpoofer = o["bootStateSpoofer"] != false,
            strongboxChainMissing = o["strongboxChainMissing"] != false,
            softwareAttested = o["softwareAttested"] != false,
            osPatchLevel = (o["osPatchLevel"] as? Number)?.toInt(),
            vendorPatchLevel = (o["vendorPatchLevel"] as? Number)?.toInt(),
            bootPatchLevel = (o["bootPatchLevel"] as? Number)?.toInt(),
            fingerprint = fp,
        )
    }

    // ---- tiny JSON writer ----------------------------------------------------
    private fun StringBuilder.comma() { append(',') }
    private fun StringBuilder.str(k: String, v: String) { append('"').append(k).append("\":"); quote(v) }
    private fun StringBuilder.strOrNull(k: String, v: String?) {
        append('"').append(k).append("\":"); if (v == null) append("null") else quote(v)
    }
    private fun StringBuilder.bool(k: String, v: Boolean) { append('"').append(k).append("\":").append(v) }
    private fun StringBuilder.num(k: String, v: Int?) {
        append('"').append(k).append("\":").append(v?.toString() ?: "null")
    }
    private fun StringBuilder.arr(v: List<String>) {
        append('['); v.forEachIndexed { i, s -> if (i > 0) append(','); quote(s) }; append(']')
    }
    private fun StringBuilder.quote(s: String) {
        append('"')
        for (c in s) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c == '\n' -> append("\\n")
            c == '\r' -> append("\\r")
            c == '\t' -> append("\\t")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }
}
