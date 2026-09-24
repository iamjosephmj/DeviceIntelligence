package tech.thessemaj.deviceintelligence.verifier

/**
 * The verify/decision vocabulary shared by every verifier path: the decision
 * enum, the check audit trail, resolved signals and the results. (The
 * scan/session facts live in ScanModel.kt; the tunable backend rules in Policy.kt.)
 */

/**
 * The final trust decision the backend makes about a token.
 *
 * - [REJECT]      — the token is not a genuine, fresh, hardware-signed binding
 *                   (forged / replayed / unbound). Never trust it.
 * - [COMPROMISED] — authentic token, but the device is compromised: the TEE's own
 *                   attestation fails an integrity gate, or a blocking signal fired.
 * - [TRUSTWORTHY] — authentic AND the TEE reports a clean device AND no blocking signal.
 */
enum class Decision { TRUSTWORTHY, COMPROMISED, REJECT }

/** Which layer a [Check] belongs to. */
enum class CheckKind { AUTH, INTEGRITY }

/** One pass/fail step of the layered decision, with a human detail string. */
data class Check(val name: String, val ok: Boolean, val detail: String, val kind: CheckKind)

/** The device context the token carries (advisory; the backend trusts the TEE, not this). */
data class DeviceInfo(val api: Int?, val abi: String?, val model: String?)

/**
 * A device finding, resolved from its opaque wire code back to meaning via the
 * registry. [detector]/[kind]/[title] are `?`/empty when the code is unknown
 * (registry drift). [blocking] is the policy verdict for this signal.
 */
data class ResolvedSignal(
    /** The opaque wire code, e.g. `INTEL_0008`. The only part the device actually sent. */
    val id: String,
    /** Detector family from the registry, e.g. `environment`. `?` when the code is unknown. */
    val detector: String,
    /** Specific finding within the family, e.g. `hook_framework_present`. `?` when unknown. */
    val kind: String,
    /** Human-readable summary from the registry. Empty when the code is unknown. */
    val title: String,
    /** Registry default severity. **A hint** — [Policy] may reweight or override it. */
    val severity: String,
    /** Free-text enrichment the device attached; parsed into [attributes]. */
    val detail: String,
    /** Whether [Policy] decided this finding blocks. This is the policy verdict, not severity. */
    val blocking: Boolean,
    /** Structured enrichment parsed from [detail] (key=value tokens the device attached). */
    val attributes: Map<String, String> = emptyMap(),
) {
    /** Injected Magisk/KSU/Zygisk module id, when the finding names one (e.g. INTEL_0035). */
    val moduleId: String? get() = attributes["module_id"]
    /** Mapping path of the injected/foreign code, if present. */
    val path: String? get() = attributes["path"]
    /** DT_NEEDED libraries of an injected module (from its mapped ELF). */
    val linkedLibraries: List<String>
        get() = attributes["needed"]?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    /** A dedicated hooking library the injected module links (confirmed hooking framework). */
    val linksHookLib: String? get() = attributes["links_hook_lib"]
    /** The hooked symbol/function, when a GOT hijack was resolved (INTEL_0036). */
    val hookedSymbol: String? get() = attributes["hooked_symbol"]
    /** The module that placed the hook, when correlated (INTEL_0036). */
    val hookedBy: String? get() = attributes["hooked_by"]
    /**
     * INTEL_0009 enrichment: how many RWX regions hold trampoline stubs that branch into REAL
     * code (legit system code or a foreign injected module) — a hook pool, as opposed to a
     * self-referential/empty region (a benign JIT cache). Null when the device did not attach it.
     */
    val hookStubRegions: Int? get() = attributes["hook_stub_regions"]?.toIntOrNull()
    /**
     * True when this is an RWX finding whose contents are a confirmed hook trampoline pool
     * (`hook_stub_regions > 0`) — RWX presence corroborated by stubs branching into real code,
     * not merely a JIT cache. This is the FP-safe half of INTEL_0009.
     */
    val isConfirmedHookPool: Boolean get() = kind == "rwx_memory_mapping" && (hookStubRegions ?: 0) > 0
}

/** The full result of [TokenVerifier.verify]. */
data class VerificationResult(
    /** The final call: [Decision.TRUSTWORTHY], [Decision.COMPROMISED] or [Decision.REJECT]. */
    val decision: Decision,
    /** Every AUTH check passed — the token is genuine and freshly bound. */
    val authentic: Boolean,
    /** Every INTEGRITY check passed — the device is in a trustworthy state. */
    val deviceIntegrityOk: Boolean,
    /** Every check that ran, in order, with its detail string. The audit trail. */
    val checks: List<Check>,
    /** Wire schema version the device produced. */
    val schemaVersion: Int?,
    /** The scan point name the app passed, e.g. `"checkout"`. */
    val point: String?,
    /** Device-reported timestamp, epoch seconds. Advisory — the device's clock. */
    val ts: Long?,
    /** The nonce this token is bound to. */
    val nonce: String?,
    /** Self-reported device context. Advisory; the TEE's attestation is authoritative. */
    val device: DeviceInfo?,
    /** Findings resolved from opaque codes to meaning. */
    val signals: List<ResolvedSignal>,
) {
    /** The blocking signals (what made an authentic token COMPROMISED). */
    val blockingSignals: List<ResolvedSignal> get() = signals.filter { it.blocking }

    /**
     * Symbols confirmed hooked by BOTH a structural signal (INTEL_0038 `libc_inline_hook` /
     * INTEL_0039 `libc_inline_stub`) AND a behavioral one (INTEL_0040 `syscall_divergence`).
     * Structural + behavioral agreement on the same symbol is a definitive, mechanism-confirmed
     * hook. This correlation is a BACKEND verdict decision (it lives here, in the code a real
     * server runs) — the client only displays what the verifier computed.
     */
    val definitiveHooks: List<String> get() = signals.definitiveHooks()

    /**
     * RWX findings (INTEL_0009) confirmed to be hook trampoline pools — their stubs branch into
     * real code (`hook_stub_regions > 0`), not a self-referential JIT cache. A confirmed hook
     * pool is a mechanism-independent corroboration of an in-process hook (Frida/LSPlant class),
     * distinct from the symbol-keyed [definitiveHooks]. Always blocking, regardless of policy tuning.
     */
    val confirmedHookPools: List<ResolvedSignal> get() = signals.confirmedHookPools()
}

// The two correlations above are pure functions of a signal list, so they live here
// rather than on one result type — every consumer (VerificationResult, ScanResult,
// a caller holding raw signals) gets the same backend verdict logic.

/** See [VerificationResult.definitiveHooks]. */
fun List<ResolvedSignal>.definitiveHooks(): List<String> {
    val structural = filter { it.kind == "libc_inline_hook" || it.kind == "libc_inline_stub" }
        .mapNotNull { it.hookedSymbol }.toSet()
    val behavioral = filter { it.kind == "syscall_divergence" }
        .mapNotNull { it.hookedSymbol }.toSet()
    return (structural intersect behavioral).sorted()
}

/** See [VerificationResult.confirmedHookPools]. */
fun List<ResolvedSignal>.confirmedHookPools(): List<ResolvedSignal> =
    filter { it.isConfirmedHookPool }

/** The result of [TokenDecoder.decode] — no verification, just the decrypted document. */
data class DecodedToken(
    /** Wire schema version the device produced. */
    val schemaVersion: Int?,
    /** The scan point name the app passed. */
    val point: String?,
    /** Device-reported timestamp, epoch seconds. */
    val ts: Long?,
    /** The nonce carried in the document. **Unverified** — nothing has been checked yet. */
    val nonce: String?,
    /** Self-reported device context. */
    val device: DeviceInfo?,
    /** Findings resolved via the registry. */
    val signals: List<ResolvedSignal>,
    /** Whether a signature binding is present. Presence only — validity is not checked here. */
    val hasBinding: Boolean,
)
