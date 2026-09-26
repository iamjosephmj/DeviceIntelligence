package tech.thessemaj.deviceintelligence.verifier

/**
 * Decrypts a token and returns its document WITHOUT verifying authenticity — the
 * Kotlin mirror of corpus/red-team/decode_token.py. Useful for inspection / logging;
 * for a trust decision use [TokenVerifier].
 */
class TokenDecoder(
    private val registry: SignalRegistry = SignalRegistry.bundled,
    private val policy: Policy = Policy(),
) {
    companion object {
        internal const val BINDING_SEP = "\n--BINDING\n"
    }

    /**
     * Decrypt and parse a token **without verifying it**. For diagnostics and tooling.
     *
     * Nothing here checks the signature, the chain, or the nonce, so the result must never
     * drive a trust decision — use [ScanVerifier.verifyScan] for that.
     */
    fun decode(tokenHex: String): DecodedToken {
        val text = Keystream.decryptHex(tokenHex)
        val signed = text.substringBefore(BINDING_SEP)
        val hasBinding = text.contains(BINDING_SEP)
        val doc = Json.parseObject(signed)
        return DecodedToken(
            schemaVersion = (doc["schemaVersion"] as? Long)?.toInt(),
            point = doc["point"] as? String,
            ts = doc["ts"] as? Long,
            nonce = doc["nonce"] as? String,
            device = Signals.device(doc),
            signals = Signals.resolve(doc, registry, policy),
            hasBinding = hasBinding,
        )
    }
}

/** Shared helpers for turning the decrypted `signed_content` into typed values. */
internal object Signals {
    @Suppress("UNCHECKED_CAST")
    /** Map the document's opaque codes to meaning and apply [policy] to decide what blocks. */
    fun resolve(doc: Map<String, Any?>, registry: SignalRegistry, policy: Policy): List<ResolvedSignal> {
        val raw = doc["signals"] as? List<Any?> ?: return emptyList()
        return raw.mapNotNull { it as? Map<String, Any?> }.map { s ->
            // Legacy prefix bridge: runtime builds from before the INTEL_ rebrand emit
            // SIG_-coded ids (and captured fixtures carry them). Normalize before the
            // registry lookup so old captures still resolve and grade.
            val rawId = s["id"] as? String ?: "INTEL_UNKNOWN"
            val id = if (rawId.startsWith("SIG_")) "INTEL_" + rawId.substring(4) else rawId
            val meta = registry[id]
            val severity = s["severity"] as? String ?: meta?.severity ?: ""
            val detail = s["detail"] as? String ?: ""
            val attrs = parseAttrs(detail)
            ResolvedSignal(
                id = id,
                detector = meta?.detector ?: "?",
                kind = meta?.kind ?: "?",
                title = meta?.title ?: "",
                severity = severity,
                detail = detail,
                blocking = policy.isBlocking(id, severity, meta?.kind, attrs["hook_stub_regions"]?.toIntOrNull()),
                attributes = attrs,
            )
        }
    }

    // The device attaches enrichment to a signal's detail as space-joined key=value
    // tokens (module_id=, path=, needed=, links_hook_lib=, hooked_symbol=, hooked_by=).
    private val ATTR_KEYS = setOf("path", "module_id", "needed", "links_hook_lib", "hooked_symbol", "hooked_by", "target", "ondisk_confirmed", "on_disk_prologue", "trampoline_class", "object", "base", "seals", "key", "get", "area", "hook_stub_regions", "region_count")
    private fun parseAttrs(detail: String): Map<String, String> {
        if (detail.isEmpty()) return emptyMap()
        val m = LinkedHashMap<String, String>()
        for (tok in detail.split(' ')) {
            val eq = tok.indexOf('=')
            if (eq > 0) { val k = tok.substring(0, eq); if (k in ATTR_KEYS) m[k] = tok.substring(eq + 1) }
        }
        return m
    }

    @Suppress("UNCHECKED_CAST")
    /** The self-reported device context, if present. Advisory — the attestation is authoritative. */
    fun device(doc: Map<String, Any?>): DeviceInfo? {
        val d = doc["device"] as? Map<String, Any?> ?: return null
        return DeviceInfo(
            api = (d["api"] as? Long)?.toInt(),
            abi = d["abi"] as? String,
            model = d["model"] as? String,
        )
    }
}
