package io.ssemaj.deviceintelligence.gradle.internal

/**
 * Hand-rolled JSON writer for [Fingerprint]. We avoid Gson/Jackson/etc. to
 * keep the plugin's runtime classpath dependency-free; the schema is small
 * and stable enough that pulling in a serializer would be overkill.
 *
 * Output is deterministic (entry keys sorted, stable formatting) so the
 * JSON itself can be hashed and compared between builds — useful for
 * caching and reproducibility checks.
 */
internal object FingerprintJson {

    fun encode(fp: Fingerprint): String = buildString {
        append("{\n")
        kv("schemaVersion", fp.schemaVersion); append(",\n")
        kv("builtAtEpochMs", fp.builtAtEpochMs); append(",\n")
        kvStr("pluginVersion", fp.pluginVersion); append(",\n")
        kvStr("variantName", fp.variantName); append(",\n")
        kvStr("applicationId", fp.applicationId); append(",\n")
        kvList("signerCertSha256", fp.signerCertSha256); append(",\n")
        kvSortedMap("entries", fp.entries); append(",\n")
        kvList("ignoredEntries", fp.ignoredEntries); append(",\n")
        kvList("ignoredEntryPrefixes", fp.ignoredEntryPrefixes); append(",\n")
        kvStr("expectedSourceDirPrefix", fp.expectedSourceDirPrefix); append(",\n")
        kvList("expectedInstallerWhitelist", fp.expectedInstallerWhitelist); append(",\n")
        kvSortedMapOfLists("nativeLibInventoryByAbi", fp.nativeLibInventoryByAbi); append(",\n")
        kvSortedNestedMap("nativeLibHashesByAbi", fp.nativeLibHashesByAbi); append(",\n")
        kvSortedMap("dicoreTextSha256ByAbi", fp.dicoreTextSha256ByAbi); append('\n')
        append("}\n")
    }

    private fun StringBuilder.kvSortedMapOfLists(
        key: String,
        map: Map<String, List<String>>,
    ) {
        append("  ").appendQuoted(key).append(": {")
        if (map.isEmpty()) {
            append('}')
            return
        }
        append('\n')
        val sortedKeys = map.keys.sorted()
        sortedKeys.forEachIndexed { i, k ->
            append("    ").appendQuoted(k).append(": [")
            val items = map.getValue(k)
            if (items.isEmpty()) {
                append(']')
            } else {
                append('\n')
                items.forEachIndexed { j, s ->
                    append("      ").appendQuoted(s)
                    if (j != items.lastIndex) append(',')
                    append('\n')
                }
                append("    ]")
            }
            if (i != sortedKeys.lastIndex) append(',')
            append('\n')
        }
        append("  }")
    }

    private fun StringBuilder.kvSortedNestedMap(
        key: String,
        map: Map<String, Map<String, String>>,
    ) {
        append("  ").appendQuoted(key).append(": {")
        if (map.isEmpty()) {
            append('}')
            return
        }
        append('\n')
        val sortedKeys = map.keys.sorted()
        sortedKeys.forEachIndexed { i, k ->
            append("    ").appendQuoted(k).append(": {")
            val sub = map.getValue(k)
            if (sub.isEmpty()) {
                append('}')
            } else {
                append('\n')
                val subKeys = sub.keys.sorted()
                subKeys.forEachIndexed { j, sk ->
                    append("      ").appendQuoted(sk).append(": ").appendQuoted(sub.getValue(sk))
                    if (j != subKeys.lastIndex) append(',')
                    append('\n')
                }
                append("    }")
            }
            if (i != sortedKeys.lastIndex) append(',')
            append('\n')
        }
        append("  }")
    }

    private fun StringBuilder.kv(key: String, value: Long) {
        append("  ").appendQuoted(key).append(": ").append(value)
    }

    private fun StringBuilder.kv(key: String, value: Int) {
        append("  ").appendQuoted(key).append(": ").append(value)
    }

    private fun StringBuilder.kvStr(key: String, value: String) {
        append("  ").appendQuoted(key).append(": ").appendQuoted(value)
    }

    private fun StringBuilder.kvList(key: String, items: List<String>) {
        append("  ").appendQuoted(key).append(": [")
        if (items.isEmpty()) {
            append(']')
            return
        }
        append('\n')
        items.forEachIndexed { i, s ->
            append("    ").appendQuoted(s)
            if (i != items.lastIndex) append(',')
            append('\n')
        }
        append("  ]")
    }

    private fun StringBuilder.kvSortedMap(key: String, map: Map<String, String>) {
        append("  ").appendQuoted(key).append(": {")
        if (map.isEmpty()) {
            append('}')
            return
        }
        append('\n')
        val sortedKeys = map.keys.sorted()
        sortedKeys.forEachIndexed { i, k ->
            append("    ").appendQuoted(k).append(": ").appendQuoted(map.getValue(k))
            if (i != sortedKeys.lastIndex) append(',')
            append('\n')
        }
        append("  }")
    }

    private fun StringBuilder.appendQuoted(s: String): StringBuilder {
        append('"')
        for (ch in s) {
            when (ch) {
                '\\' -> append("\\\\")
                '"'  -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                '\b' -> append("\\b")
                else -> if (ch.code < 0x20) {
                    append("\\u%04x".format(ch.code))
                } else {
                    append(ch)
                }
            }
        }
        append('"')
        return this
    }
}
