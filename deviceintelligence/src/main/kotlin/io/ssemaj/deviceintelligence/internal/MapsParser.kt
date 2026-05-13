package io.ssemaj.deviceintelligence.internal

/**
 * Pure parser for `/proc/self/maps` content. Split out from
 * [RuntimeEnvironmentDetector] so the line-by-line scanning logic is
 * unit-testable without JNI / a live `/proc/self/maps`.
 *
 * The procfs maps line format is fixed across every Linux kernel
 * Android ships (see `man 5 proc`):
 *
 * ```
 * address           perms offset  dev   inode   pathname
 * 7fa3a92000-7fa3a93000 rw-p 00001000 fd:00 1234   /data/.../libfoo.so
 * ```
 *
 * We only care about two columns:
 *  - `perms` (4 chars: r/w/x/p+s) — looking for executable RW pages
 *    (`rwxp`/`rwxs`). Legitimate Android binaries never have these
 *    after the loader maps them: page mappings are either RX (code),
 *    RW (data), or R (ro-data). RWX is exclusively the JIT region of
 *    a hot-patch trampoline or in-process binary patcher.
 *  - `pathname` — looking for known hooking-framework signatures
 *    (Frida agent, Substrate, Xposed, LSPosed/Riru/Zygisk, etc.).
 *
 * Anonymous mappings (no pathname) and [vdso]/[stack]/[heap]
 * pseudo-paths are still surfaced as RWX hits when applicable —
 * anonymous RWX is the textbook signature of an injected JIT
 * trampoline.
 */
internal object MapsParser {

    /**
     * Names matched against the `pathname` column of each maps line.
     * Match is case-sensitive substring (kept simple: false-negative
     * on weird casings is acceptable; false-positive on legitimate
     * libs would be much worse).
     *
     * Sources behind each entry:
     *  - `frida-agent`, `frida-gadget`, `gum-js-loop`: Frida's
     *    JavaScript bridge and trampoline thread name leak into the
     *    process map when the gadget is injected.
     *  - `libsubstrate`, `cydiasubstrate`: Cydia Substrate / Saurik's
     *    MobileSubstrate Android port.
     *  - `libxposed`, `XposedBridge.jar`: classic Xposed framework
     *    artifacts loaded into the Zygote child.
     *  - `LSPosed`, `lspd`: LSPosed (modern Xposed reimplementation)
     *    daemon and helper.
     *  - `libriru`, `libzygisk`: Riru / Zygisk loaders that LSPosed
     *    and other Magisk modules rely on.
     *  - `libtaichi`: Taichi (Xposed-on-non-rooted-devices framework).
     *  - `libdobby`, `dobby_bridge`: Dobby — general-purpose ARM
     *    inline-hook lib (github.com/jmpews/Dobby). The
     *    `dobby_bridge` symbol-name shows up in maps even for
     *    statically-linked uses, making this a strong signal.
     *  - `libwhale`: Whale — Java method-hook framework
     *    (github.com/asLody/whale). EdXposed-adjacent; minimal
     *    legitimate-embed risk.
     *  - `libyahfa`: YAHFA — "Yet Another Hook Framework for ART"
     *    (github.com/PAGalaxyLab/YAHFA). Used as the ART-side
     *    backend by EdXposed and some LSPosed configurations.
     *  - `libfasthook`: FastHook
     *    (github.com/turing-technician/FastHook). Niche but
     *    seen in game-modding kits.
     *  - `libil2cppdumper`, `zygisk-il2cpp`: zygisk-il2cpp-dumper —
     *    Zygisk module that dumps Unity IL2CPP game logic. Common
     *    on cheating frameworks targeting Unity-based games.
     *
     * NOT in this list (intentionally — known false-positive risk):
     *  - **ShadowHook** (`libshadowhook`) — open-sourced by Bytedance
     *    and shipped IN their own apps (TikTok, Douyin, CapCut,
     *    Lemon8) for legitimate in-app patching. Detecting the
     *    library name alone would FP on every Bytedance install.
     *    Catching ShadowHook-driven attacks specifically requires
     *    the embedded-vs-injected distinction (cross-reference
     *    against the consumer app's build-time native-lib
     *    inventory). Tracked under CTF_ROADMAP for a future
     *    release.
     *  - **SandHook** (`libsandhook`), **Pine** (`libpine`) — used
     *    as ART-hook backends by both attack tooling AND some
     *    legitimate game-cheat-prevention frameworks. Same
     *    embedded-vs-injected distinction needed before adding.
     */
    internal val HOOK_FRAMEWORK_SIGNATURES: List<HookFramework> = listOf(
        HookFramework("frida", listOf("frida-agent", "frida-gadget", "gum-js-loop")),
        HookFramework("substrate", listOf("libsubstrate", "cydiasubstrate")),
        HookFramework("xposed", listOf("libxposed", "XposedBridge.jar")),
        HookFramework("lsposed", listOf("LSPosed", "lspd_")),
        HookFramework("riru", listOf("libriru")),
        HookFramework("zygisk", listOf("libzygisk")),
        HookFramework("taichi", listOf("libtaichi")),
        HookFramework("dobby", listOf("libdobby", "dobby_bridge")),
        HookFramework("whale", listOf("libwhale")),
        HookFramework("yahfa", listOf("libyahfa")),
        HookFramework("fasthook", listOf("libfasthook")),
        HookFramework("il2cpp_dumper", listOf("libil2cppdumper", "zygisk-il2cpp")),
    )

    internal data class HookFramework(val canonicalName: String, val signatures: List<String>)

    /**
     * One `[anon:dalvik-...]` mapping line. Surfaced separately
     * from [parse]'s [ScanResult] because [DexInjection]
     * is the only consumer and it cares about a different shape
     * of the same maps content (label string + address range,
     * not perms/path).
     *
     * `label` is the substring INSIDE the brackets — e.g.
     * `"anon:dalvik-classes.dex extracted in memory from <path>"` —
     * stripped of the surrounding `[` `]`. The leading
     * `anon:dalvik-` prefix is preserved so callers can filter
     * other named-anon families (`[anon:libc_malloc]` etc) by
     * looking at the same string.
     */
    internal data class DalvikAnonRegion(
        val addressRange: String,
        val perms: String,
        val label: String,
    )

    /**
     * Result of one [parse] call. Empty lists mean no hits — the
     * detector emits zero findings in that case.
     */
    internal data class ScanResult(
        /** One canonical name per distinct framework matched. Order matches first-seen-line. */
        val hookFrameworks: List<String>,
        /**
         * Region descriptors for every `rwxp` / `rwxs` line. Format
         * `"<address-range> <pathname-or-anon>"`, e.g.
         * `"7fa39e0000-7fa39e2000 [anon]"`. Capped at [RWX_REGION_LIMIT]
         * entries to keep finding details bounded; if the limit is
         * hit, the last entry is `"... +N more"` so the caller knows
         * truncation happened.
         *
         * NOTE: this list includes memfd-backed regions that also
         * match the [fridaMemfdJitRegions] pattern — the more
         * specific Frida-attribution signal does NOT remove the
         * region from this generic list, so a backend that only
         * keys on `rwx_memory_mapping` still sees the hit.
         */
        val rwxRegions: List<String>,
        /**
         * Subset of [rwxRegions] that match the Frida 16+ memfd-backed
         * Gum JIT signature: `/memfd:jit-cache` with `rwxp` perms AND
         * region size > 8 MB. ART maps `/memfd:jit-cache` legitimately
         * but only with `r-xp` / `r--p` perms; requiring `rwxp` plus
         * the 8 MB lower bound eliminates ART false-positives observed
         * on Samsung/Android 16 builds (technique credit: snitchtt
         * project — implemented clean-room from the published
         * description, no source borrowed since the library uses an
         * Apache-2.0-incompatible Commons Clause restriction).
         */
        val fridaMemfdJitRegions: List<String>,
    )

    private const val RWX_REGION_LIMIT = 8
    private const val FRIDA_MEMFD_JIT_MIN_SIZE = 8L * 1024 * 1024
    private const val MEMFD_JIT_CACHE_SUBSTRING = "/memfd:jit-cache"

    /**
     * Single-pass scanner. Splits [content] on '\n' (procfs always
     * uses Unix newlines) and walks each line.
     */
    internal fun parse(content: String): ScanResult {
        val foundFrameworks = LinkedHashSet<String>()
        val rwxRegions = ArrayList<String>(RWX_REGION_LIMIT + 1)
        val fridaMemfdJitRegions = ArrayList<String>()
        var rwxOverflow = 0

        for (line in content.lineSequence()) {
            if (line.isEmpty()) continue
            // Format: "ADDR PERMS OFFSET DEV INODE PATHNAME"
            // Pathname is everything after the 5th whitespace block.
            val firstSpace = line.indexOf(' ')
            if (firstSpace <= 0 || firstSpace + 5 >= line.length) continue
            val perms = line.substring(firstSpace + 1, minOf(firstSpace + 5, line.length))
            val pathname = extractPathname(line)
            val addressRange = line.substring(0, firstSpace)

            // RWX detection is purely on perms; pathname is captured
            // for the finding details only. Catches both `rwxp`
            // (private, the common case) and `rwxs` (shared, rarer
            // but equally suspicious).
            val isRwx = perms.length == 4 && perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x'
            if (isRwx) {
                if (rwxRegions.size < RWX_REGION_LIMIT) {
                    val descriptor = if (pathname.isEmpty()) {
                        "$addressRange [anon]"
                    } else {
                        "$addressRange $pathname"
                    }
                    rwxRegions += descriptor
                } else {
                    rwxOverflow++
                }

                // Frida 16+ Gum JIT signature: `/memfd:jit-cache`
                // mapped `rwxp` AND >8 MB. ART legitimately maps the
                // same path but only with `r-xp`/`r--p` perms — the
                // outer `isRwx` already excludes the legitimate case
                // by perms, the size threshold is belt-and-suspenders
                // against transient hooker scratch pages.
                if (pathname.contains(MEMFD_JIT_CACHE_SUBSTRING) &&
                    regionSizeBytes(addressRange).let { it != null && it > FRIDA_MEMFD_JIT_MIN_SIZE }
                ) {
                    fridaMemfdJitRegions += "$addressRange $pathname"
                }
            }

            // Hook-framework detection: only meaningful when there's
            // a pathname (anonymous mappings can't be a named lib).
            if (pathname.isNotEmpty()) {
                for (fw in HOOK_FRAMEWORK_SIGNATURES) {
                    for (sig in fw.signatures) {
                        if (pathname.contains(sig)) {
                            foundFrameworks += fw.canonicalName
                            break
                        }
                    }
                }
            }
        }

        if (rwxOverflow > 0) {
            rwxRegions += "... +$rwxOverflow more"
        }

        return ScanResult(
            hookFrameworks = foundFrameworks.toList(),
            rwxRegions = rwxRegions,
            fridaMemfdJitRegions = fridaMemfdJitRegions,
        )
    }

    /**
     * Parse a maps `address` column ("START-END" hex) into the
     * region size in bytes. Returns null when the column is
     * malformed or the values can't be parsed as unsigned hex
     * longs; callers treat null as "size unknown, do not flag".
     *
     * `Long.parseLong(...16)` would overflow on `0xFFFF_FFFF_FFFF_FFFF`-
     * shaped values; we use [toULong] for the unsigned parse and
     * cap the size at `Long.MAX_VALUE` since any region that
     * approaches that limit is far past our 8 MB threshold anyway.
     */
    private fun regionSizeBytes(addressRange: String): Long? {
        val dash = addressRange.indexOf('-')
        if (dash <= 0 || dash + 1 >= addressRange.length) return null
        val start = runCatching { addressRange.substring(0, dash).toULong(16) }.getOrNull()
        val end = runCatching { addressRange.substring(dash + 1).toULong(16) }.getOrNull()
        if (start == null || end == null || end <= start) return null
        val size = end - start
        return if (size > Long.MAX_VALUE.toULong()) Long.MAX_VALUE else size.toLong()
    }

    /**
     * Walks [content] and returns one [DalvikAnonRegion] per line
     * whose pathname is a `[anon:dalvik-...]` named-anon mapping.
     * The Linux kernel exposes `prctl(PR_SET_VMA_ANON_NAME, ...)`
     * names in the pathname column verbatim, surrounded by `[ ]`,
     * so a substring scan is sufficient.
     *
     * Used by [DexInjection]'s channel (b) to identify
     * regions ART has minted to hold extracted DEX bytes —
     * [InMemoryDexClassLoader] payloads in particular surface as
     * `[anon:dalvik-classes.dex extracted in memory from <buffer>]`.
     *
     * Returns regions in first-seen order. Caller is expected to
     * classify each label and decide whether it represents a
     * legitimate ART internals region (jit-cache, zygote-claimed,
     * GC heap) or an injected-DEX region.
     */
    internal fun scanDalvikAnonRegions(content: String): List<DalvikAnonRegion> {
        val out = ArrayList<DalvikAnonRegion>()
        for (line in content.lineSequence()) {
            if (line.isEmpty()) continue
            val open = line.indexOf("[anon:dalvik-")
            if (open < 0) continue
            val close = line.indexOf(']', open)
            if (close < 0) continue
            val firstSpace = line.indexOf(' ')
            if (firstSpace <= 0 || firstSpace + 5 > line.length) continue
            val perms = line.substring(firstSpace + 1, firstSpace + 5)
            val addressRange = line.substring(0, firstSpace)
            val label = line.substring(open + 1, close)
            out += DalvikAnonRegion(
                addressRange = addressRange,
                perms = perms,
                label = label,
            )
        }
        return out
    }

    /**
     * Pulls the pathname out of one maps line. Pathname starts after
     * the 5th whitespace-separated column; whitespace is collapsed
     * (procfs uses single spaces but we tolerate runs of them).
     * Returns "" when there is no pathname (anonymous mapping).
     */
    private fun extractPathname(line: String): String {
        var i = 0
        var fields = 0
        // Skip 5 whitespace-delimited fields.
        while (i < line.length && fields < 5) {
            // skip non-ws
            while (i < line.length && line[i] != ' ' && line[i] != '\t') i++
            // skip ws
            while (i < line.length && (line[i] == ' ' || line[i] == '\t')) i++
            fields++
        }
        if (i >= line.length) return ""
        // Trim any trailing '\n' the caller didn't strip.
        var end = line.length
        while (end > i && (line[end - 1] == '\n' || line[end - 1] == '\r')) end--
        return line.substring(i, end)
    }
}
