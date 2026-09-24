package tech.thessemaj.deviceintelligence.verifier

/** One registry entry: an opaque code and the meaning the backend resolves it to. */
data class SignalMeta(
    /** The opaque wire code, e.g. `INTEL_0008`. */
    val id: String,
    /** Detector family, e.g. `environment`. */
    val detector: String,
    /** Specific finding within the family, e.g. `hook_framework_present`. */
    val kind: String,
    /** Registry default severity. A hint — [Policy] decides what actually blocks. */
    val severity: String,
    /** One-line human summary. */
    val title: String,
    /** What the detector observed and what it implies. */
    val description: String,
)

/**
 * The code↔meaning map. The device emits only opaque `INTEL_xxxx` codes; this
 * resolves each back to detector/kind/severity/title for policy and display.
 *
 * The default instance ([bundled]) loads `signals-registry.json` from the library
 * resources — the very file `tools/registry/signals-registry.json`, copied in at build time
 * so the verifier and the on-device emitter never drift.
 */
class SignalRegistry(private val byId: Map<String, SignalMeta>) {

    operator fun get(id: String?): SignalMeta? = if (id == null) null else byId[id]

    /** How many signal rows are loaded. Zero means the registry failed to load. */
    val size: Int get() = byId.size

    companion object {
        private const val RESOURCE = "/signals-registry.json"

        val bundled: SignalRegistry by lazy { fromResource(RESOURCE) }

        fun fromResource(path: String): SignalRegistry {
            val text = SignalRegistry::class.java.getResourceAsStream(path)
                ?.bufferedReader()?.use { it.readText() }
                ?: throw IllegalStateException("signal registry resource not found: $path")
            return fromJson(text)
        }

        @Suppress("UNCHECKED_CAST")
        fun fromJson(text: String): SignalRegistry {
            val root = Json.parseObject(text)
            val signals = root["signals"] as? List<Any?> ?: emptyList()
            val map = LinkedHashMap<String, SignalMeta>()
            for (s in signals) {
                val o = s as? Map<String, Any?> ?: continue
                val id = o["id"] as? String ?: continue
                if (o["status"] == "retired") continue
                map[id] = SignalMeta(
                    id = id,
                    detector = o["detector"] as? String ?: "?",
                    kind = o["kind"] as? String ?: "?",
                    severity = o["severity"] as? String ?: "",
                    title = o["title"] as? String ?: "",
                    description = o["description"] as? String ?: "",
                )
            }
            return SignalRegistry(map)
        }
    }
}
