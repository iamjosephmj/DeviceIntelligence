package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.AttestationReport
import io.ssemaj.deviceintelligence.CertValidity
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.DeviceContext
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.InstallSource
import io.ssemaj.deviceintelligence.ReportSummary
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.TelemetryReport

/**
 * Hand-rolled JSON writer for [TelemetryReport].
 *
 * Avoids kotlinx.serialization / Gson / Jackson / Moshi to keep the
 * AAR's runtime classpath dependency-free — DeviceIntelligence is a security
 * library and every transitive dependency is one more potential
 * attack surface and a few more KB of dex.
 *
 * Output is deterministic (per-detector preserved order, summary
 * keys in enum order, finding details sorted by key, fields in a
 * stable layout) so a backend can hash an entire report for cheap
 * de-duplication if it wants.
 *
 * Status values use lowercase snake_case strings (`"ok"`,
 * `"inconclusive"`, `"error"`) and severity values use lowercase
 * (`"low"`, `"medium"`, `"high"`, `"critical"`). This matches the
 * convention most JSON consumers reach for and decouples the wire
 * format from the Kotlin enum spelling.
 */
internal object TelemetryJson {

    fun encode(r: TelemetryReport): String = buildString {
        append("{\n")
        kvInt("schema_version", r.schemaVersion); append(",\n")
        kvStr("library_version", r.libraryVersion); append(",\n")
        kvLong("collected_at_epoch_ms", r.collectedAtEpochMs); append(",\n")
        kvLong("collection_duration_ms", r.collectionDurationMs); append(",\n")
        kvObject("device", indent = "  ") { encodeDevice(r.device, it) }
        append(",\n")
        kvObject("app", indent = "  ") { encodeApp(r.app, it) }
        append(",\n")
        kvArray("detectors", indent = "  ", items = r.detectors) { item, indent ->
            encodeDetector(item, indent)
        }
        append(",\n")
        kvObject("summary", indent = "  ") { encodeSummary(r.summary, it) }
        append('\n')
        append("}\n")
    }

    // ---- device / app ------------------------------------------------------

    private fun StringBuilder.encodeDevice(d: DeviceContext, indent: String) {
        kvStr("manufacturer", d.manufacturer, indent); append(",\n")
        kvStr("model", d.model, indent); append(",\n")
        kvInt("sdk_int", d.sdkInt, indent); append(",\n")
        kvStr("abi", d.abi, indent); append(",\n")
        kvStr("fingerprint", d.fingerprint, indent); append(",\n")
        // Observability fields. Each may be null; the JSON encoder
        // emits `null` for unavailable values rather than omitting
        // the key entirely so backends always see the same shape.
        kvLongOrNull("total_ram_mb", d.totalRamMb, indent); append(",\n")
        kvIntOrNull("cpu_cores", d.cpuCores, indent); append(",\n")
        kvIntOrNull("screen_density_dpi", d.screenDensityDpi, indent); append(",\n")
        kvStrOrNull("screen_resolution", d.screenResolution, indent); append(",\n")
        kvBoolOrNull("has_fingerprint_hw", d.hasFingerprintHw, indent); append(",\n")
        kvBoolOrNull("has_telephony_hw", d.hasTelephonyHw, indent); append(",\n")
        kvIntOrNull("sensor_count", d.sensorCount, indent); append(",\n")
        kvIntOrNull("boot_count", d.bootCount, indent); append(",\n")
        kvBoolOrNull("vpn_active", d.vpnActive, indent); append(",\n")
        kvBoolOrNull("strongbox_available", d.strongboxAvailable, indent); append('\n')
    }

    private fun StringBuilder.encodeApp(a: AppContext, indent: String) {
        kvStr("package_name", a.packageName, indent); append(",\n")
        kvStrOrNull("apk_path", a.apkPath, indent); append(",\n")
        kvStrOrNull("installer_package", a.installerPackage, indent); append(",\n")
        kvList("signer_cert_sha256", a.signerCertSha256, indent); append(",\n")
        kvStrOrNull("build_variant", a.buildVariant, indent); append(",\n")
        kvStrOrNull("library_plugin_version", a.libraryPluginVersion, indent); append(",\n")
        kvLongOrNull("first_install_epoch_ms", a.firstInstallEpochMs, indent); append(",\n")
        kvLongOrNull("last_update_epoch_ms", a.lastUpdateEpochMs, indent); append(",\n")
        kvIntOrNull("target_sdk_version", a.targetSdkVersion, indent); append(",\n")
        // install_source is the richer struct; installer_package
        // above is the backward-compatible flat scalar that mirrors
        // install_source.installing_package.
        val installSource = a.installSource
        if (installSource == null) {
            append(indent).appendQuoted("install_source").append(": null,\n")
        } else {
            kvObject("install_source", indent = indent) { encodeInstallSource(installSource, it) }
            append(",\n")
        }
        // signer_cert_validity follows the same null-vs-empty-vs-list
        // convention as signer_cert_sha256 above; null means lookup
        // failed, [] means no signers, [..] means each signer's
        // validity period in the same order.
        val validity = a.signerCertValidity
        if (validity == null) {
            append(indent).appendQuoted("signer_cert_validity").append(": null,\n")
        } else {
            kvCertValidityArray("signer_cert_validity", validity, indent); append(",\n")
        }
        // attestation is the always-shipped raw evidence + advisory
        // verdict from F14. Null only on the rare path where F14's
        // detector returned without producing a report (e.g. native
        // bridge unavailable); the library's minSdk is 28 so the
        // "device doesn't support attestation at all" case is no
        // longer reachable at runtime.
        val att = a.attestation
        if (att == null) {
            append(indent).appendQuoted("attestation").append(": null\n")
        } else {
            kvObject("attestation", indent = indent) { encodeAttestation(att, it) }
            append('\n')
        }
    }

    private fun StringBuilder.encodeInstallSource(s: InstallSource, indent: String) {
        kvStrOrNull("installing_package", s.installingPackage, indent); append(",\n")
        kvStrOrNull("originating_package", s.originatingPackage, indent); append(",\n")
        kvStrOrNull("initiating_package", s.initiatingPackage, indent); append('\n')
    }

    /**
     * Inline array of `{not_before_epoch_ms, not_after_epoch_ms}`
     * objects. One entry per signer, same order as
     * [AppContext.signerCertSha256]. Empty list serializes as `[]`.
     */
    private fun StringBuilder.kvCertValidityArray(
        k: String,
        items: List<CertValidity>,
        indent: String,
    ) {
        append(indent).appendQuoted(k).append(": [")
        if (items.isEmpty()) {
            append(']')
            return
        }
        append('\n')
        items.forEachIndexed { i, cv ->
            append(indent).append("  { ")
                .appendQuoted("not_before_epoch_ms").append(": ").append(cv.notBeforeEpochMs)
                .append(", ")
                .appendQuoted("not_after_epoch_ms").append(": ").append(cv.notAfterEpochMs)
                .append(" }")
            if (i != items.lastIndex) append(',')
            append('\n')
        }
        append(indent).append(']')
    }

    /**
     * Trimmed JSON view of [AttestationReport]. Drops the heavy
     * diagnostic fields ([AttestationReport.chainB64],
     * [AttestationReport.attestationChallengeB64],
     * [AttestationReport.attestedApplicationIdSha256],
     * [AttestationReport.verifiedBootKeySha256],
     * [AttestationReport.keymasterVersion],
     * [AttestationReport.osVersion],
     * [AttestationReport.vendorPatchLevel],
     * [AttestationReport.bootPatchLevel]) so the wire format stays
     * compact. Backends that need the chain bytes for authoritative
     * re-verification read them off the typed report directly
     * (`report.app.attestation.chainB64`); the JSON ships
     * [AttestationReport.chainSha256] for cheap correlation / dedup.
     */
    private fun StringBuilder.encodeAttestation(att: AttestationReport, indent: String) {
        kvStrOrNull("chain_sha256", att.chainSha256, indent); append(",\n")
        kvInt("chain_length", att.chainLength, indent); append(",\n")
        kvStrOrNull("attestation_security_level", att.attestationSecurityLevel, indent); append(",\n")
        kvStrOrNull("keymaster_security_level", att.keymasterSecurityLevel, indent); append(",\n")
        kvBoolOrNull("software_backed", att.softwareBacked, indent); append(",\n")
        kvStrOrNull("verified_boot_state", att.verifiedBootState, indent); append(",\n")
        kvBoolOrNull("device_locked", att.deviceLocked, indent); append(",\n")
        kvIntOrNull("os_patch_level", att.osPatchLevel, indent); append(",\n")
        kvStrOrNull("attested_package_name", att.attestedPackageName, indent); append(",\n")
        kvList("attested_signer_cert_sha256", att.attestedSignerCertSha256, indent); append(",\n")
        kvStrOrNull("verdict_device_recognition", att.verdictDeviceRecognition, indent); append(",\n")
        kvStrOrNull("verdict_app_recognition", att.verdictAppRecognition, indent); append(",\n")
        kvStrOrNull("verdict_reason", att.verdictReason, indent); append(",\n")
        kvBool("verdict_authoritative", att.verdictAuthoritative, indent); append(",\n")
        kvStrOrNull("unavailable_reason", att.unavailableReason, indent); append('\n')
    }

    // ---- detectors / findings ---------------------------------------------

    private fun StringBuilder.encodeDetector(r: DetectorReport, indent: String) {
        kvStr("id", r.id, indent); append(",\n")
        kvStr("status", statusToWire(r.status), indent); append(",\n")
        kvLong("duration_ms", r.durationMs, indent); append(",\n")
        kvStrOrNull("inconclusive_reason", r.inconclusiveReason, indent); append(",\n")
        kvStrOrNull("error_message", r.errorMessage, indent); append(",\n")
        kvArrayInline("findings", r.findings, indent) { finding, innerIndent ->
            encodeFinding(finding, innerIndent)
        }
        append('\n')
    }

    private fun StringBuilder.encodeFinding(f: Finding, indent: String) {
        kvStr("kind", f.kind, indent); append(",\n")
        kvStr("severity", severityToWire(f.severity), indent); append(",\n")
        kvStrOrNull("subject", f.subject, indent); append(",\n")
        kvStr("message", f.message, indent); append(",\n")
        kvSortedStringMap("details", f.details, indent); append('\n')
    }

    // ---- summary -----------------------------------------------------------

    private fun StringBuilder.encodeSummary(s: ReportSummary, indent: String) {
        kvInt("total_findings", s.totalFindings, indent); append(",\n")
        // Severity buckets emitted in enum order, always all four
        // present (zero-value buckets included so backends can rely
        // on the schema).
        append(indent).appendQuoted("findings_by_severity").append(": {")
        if (s.findingsBySeverity.isEmpty()) {
            append("}")
        } else {
            append('\n')
            val entries = Severity.values().map { it to (s.findingsBySeverity[it] ?: 0) }
            entries.forEachIndexed { i, (sev, n) ->
                append(indent).append("  ")
                    .appendQuoted(severityToWire(sev)).append(": ").append(n)
                if (i != entries.lastIndex) append(',')
                append('\n')
            }
            append(indent).append('}')
        }
        append(",\n")
        kvSortedIntMap("findings_by_kind", s.findingsByKind, indent); append(",\n")
        kvList("detectors_with_findings", s.detectorsWithFindings, indent); append(",\n")
        kvList("detectors_inconclusive", s.detectorsInconclusive, indent); append(",\n")
        kvList("detectors_errored", s.detectorsErrored, indent); append('\n')
    }

    // ---- enum mappings -----------------------------------------------------

    private fun statusToWire(s: DetectorStatus): String = when (s) {
        DetectorStatus.OK -> "ok"
        DetectorStatus.INCONCLUSIVE -> "inconclusive"
        DetectorStatus.ERROR -> "error"
    }

    private fun severityToWire(s: Severity): String = when (s) {
        Severity.LOW -> "low"
        Severity.MEDIUM -> "medium"
        Severity.HIGH -> "high"
        Severity.CRITICAL -> "critical"
    }

    // ---- low-level builders ------------------------------------------------

    private fun StringBuilder.kvInt(k: String, v: Int, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ").append(v)
    }

    private fun StringBuilder.kvIntOrNull(k: String, v: Int?, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ")
        if (v == null) append("null") else append(v)
    }

    private fun StringBuilder.kvBool(k: String, v: Boolean, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ").append(if (v) "true" else "false")
    }

    private fun StringBuilder.kvBoolOrNull(k: String, v: Boolean?, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ")
        if (v == null) append("null") else append(if (v) "true" else "false")
    }

    private fun StringBuilder.kvLong(k: String, v: Long, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ").append(v)
    }

    private fun StringBuilder.kvLongOrNull(k: String, v: Long?, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ")
        if (v == null) append("null") else append(v)
    }

    private fun StringBuilder.kvStr(k: String, v: String, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ").appendQuoted(v)
    }

    private fun StringBuilder.kvStrOrNull(k: String, v: String?, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": ")
        if (v == null) append("null") else appendQuoted(v)
    }

    private fun StringBuilder.kvList(k: String, items: List<String>, indent: String = "  ") {
        append(indent).appendQuoted(k).append(": [")
        if (items.isEmpty()) {
            append(']')
            return
        }
        append('\n')
        items.forEachIndexed { i, s ->
            append(indent).append("  ").appendQuoted(s)
            if (i != items.lastIndex) append(',')
            append('\n')
        }
        append(indent).append(']')
    }

    private fun StringBuilder.kvSortedStringMap(
        k: String,
        m: Map<String, String>,
        indent: String = "  ",
    ) {
        append(indent).appendQuoted(k).append(": {")
        if (m.isEmpty()) {
            append('}')
            return
        }
        append('\n')
        val keys = m.keys.sorted()
        keys.forEachIndexed { i, kk ->
            append(indent).append("  ").appendQuoted(kk).append(": ")
                .appendQuoted(m.getValue(kk))
            if (i != keys.lastIndex) append(',')
            append('\n')
        }
        append(indent).append('}')
    }

    private fun StringBuilder.kvSortedIntMap(
        k: String,
        m: Map<String, Int>,
        indent: String = "  ",
    ) {
        append(indent).appendQuoted(k).append(": {")
        if (m.isEmpty()) {
            append('}')
            return
        }
        append('\n')
        val keys = m.keys.sorted()
        keys.forEachIndexed { i, kk ->
            append(indent).append("  ").appendQuoted(kk).append(": ").append(m.getValue(kk))
            if (i != keys.lastIndex) append(',')
            append('\n')
        }
        append(indent).append('}')
    }

    private inline fun StringBuilder.kvObject(
        k: String,
        indent: String,
        body: StringBuilder.(String) -> Unit,
    ) {
        append(indent).appendQuoted(k).append(": {\n")
        body("$indent  ")
        append(indent).append('}')
    }

    private inline fun <T> StringBuilder.kvArray(
        k: String,
        indent: String,
        items: List<T>,
        body: StringBuilder.(T, String) -> Unit,
    ) {
        append(indent).appendQuoted(k).append(": [")
        if (items.isEmpty()) {
            append(']')
            return
        }
        append('\n')
        items.forEachIndexed { i, item ->
            append(indent).append("  {\n")
            body(item, "$indent    ")
            append(indent).append("  }")
            if (i != items.lastIndex) append(',')
            append('\n')
        }
        append(indent).append(']')
    }

    /** kvArray that keeps slightly tighter indentation suitable for nested list blocks. */
    private inline fun <T> StringBuilder.kvArrayInline(
        k: String,
        items: List<T>,
        indent: String,
        body: StringBuilder.(T, String) -> Unit,
    ) {
        append(indent).appendQuoted(k).append(": [")
        if (items.isEmpty()) {
            append(']')
            return
        }
        append('\n')
        items.forEachIndexed { i, item ->
            append(indent).append("  {\n")
            body(item, "$indent    ")
            append(indent).append("  }")
            if (i != items.lastIndex) append(',')
            append('\n')
        }
        append(indent).append(']')
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
