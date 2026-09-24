package tech.thessemaj.deviceintelligence.verifier

/**
 * Server-side policy — the false-positive tuning that lives OFF the device.
 * A signal blocks (marks the device compromised) when its severity is in
 * [blockSeverities], UNLESS its code is in [allow]; a code in [block] always
 * blocks regardless of severity. Defaults match tools/server/verify_token.py.
 */
data class Policy(
    /** Severities that block by default. */
    val blockSeverities: Set<String> = setOf("CRITICAL"),
    /** Codes that never block, whatever their severity. Your false-positive escape hatch. */
    val allow: Set<String> = emptySet(),
    /** Codes that always block, whatever their severity. Takes precedence over severity. */
    val block: Set<String> = emptySet(),
    /** High-assurance tier: reject any attestation weaker than StrongBox (TEE-only -> COMPROMISED). */
    val requireStrongBox: Boolean = false,
    /**
     * INTEL_0047 window: how old the OLDEST attested patch level may be, in days.
     * Modelled on Play Integrity's recent-security-update requirement. Lives here,
     * not on the device, so it can be retuned without an app release.
     */
    val maxPatchAgeDays: Int = 365,
    /**
     * Opt-in FP tuning for INTEL_0009 (rwx_memory_mapping), enabled by the per-region hook-stub
     * enrichment the device now attaches. RWX presence alone is ambiguous — a benign JIT code
     * cache is RWX too. When true, an RWX finding with NO resolved hook stubs
     * (`hook_stub_regions == 0`) is downgraded to observe (non-blocking), while a confirmed hook
     * pool (`> 0`) still blocks. Default false preserves the historic behavior (bare RWX blocks
     * on its CRITICAL severity). A confirmed hook pool ALWAYS blocks regardless of this flag.
     */
    val observeUnconfirmedRwx: Boolean = false,
) {
    fun isBlocking(id: String?, severity: String?, kind: String? = null, hookStubRegions: Int? = null): Boolean = when {
        id != null && id in allow -> false
        id != null && id in block -> true
        // A confirmed hook pool (RWX region whose stubs branch into real code) always blocks.
        kind == "rwx_memory_mapping" && (hookStubRegions ?: 0) > 0 -> true
        // Opt-in: an RWX region with no resolved hook stubs may be a benign JIT cache — observe.
        observeUnconfirmedRwx && kind == "rwx_memory_mapping" && (hookStubRegions ?: 0) == 0 -> false
        else -> (severity ?: "").uppercase() in blockSeverities
    }
}
