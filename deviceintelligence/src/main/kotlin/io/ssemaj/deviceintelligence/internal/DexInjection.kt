package io.ssemaj.deviceintelligence.internal

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log
import dalvik.system.BaseDexClassLoader
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity

/**
 * Runtime DEX-injection scanner — internal helper of
 * [RuntimeEnvironmentDetector] (NOT a [Detector] of its own).
 *
 * Catches the class of attacks that loads new bytecode into the
 * running process **without** loading a foreign `.so`, **without**
 * patching any `ArtMethod`, and **without** allocating an `RWX`
 * page. The two real-world variants this is built for:
 *
 *  1. `InMemoryDexClassLoader(ByteBuffer, parent)` — DEX bytes
 *     never touch disk. ART parks them in named anonymous mappings
 *     of the shape `[anon:dalvik-DEX data]` (Android 14+) or
 *     `[anon:dalvik-classes.dex extracted in memory from <buffer>]`
 *     (≤ Android 13). The bytes themselves live in `RW`, not
 *     `RWX`. Every existing detector stays quiet:
 *      - [MapsParser]'s RWX scan: no `RWX` page.
 *      - `lib_inventory`'s native scan: no `.so` loaded.
 *      - [ArtIntegrityDetector]'s vectors A/C/D/E/F: no existing
 *        `ArtMethod` tampered with — the payload runs as new methods
 *        on a brand-new class.
 *  2. `DexClassLoader(path, ...)` pointed at a payload dropped by a
 *     Zygisk module under `/data/local/tmp/`, `/data/data/<other-pkg>/`,
 *     or any path outside the app's APK split set. The DexFile is
 *     registered in ART without any of the classic hooking signals.
 *
 * **Why this is a helper inside `runtime.environment` rather than
 * a detector of its own:** DEX injection is bytecode-level
 * tampering of the running process and conceptually belongs in
 * the same bucket as [RuntimeEnvironmentDetector]'s existing
 * hook-framework / RWX / GOT / `.text` scans. All findings emitted
 * here flow through the `runtime.environment` detector report and
 * map to [io.ssemaj.deviceintelligence.IntegritySignal.HOOKING_FRAMEWORK_DETECTED].
 *
 * Two independent channels — either firing is sufficient evidence:
 *
 *  - **Channel (a) — ClassLoader-chain diff.** Walks every
 *    [BaseDexClassLoader] reachable from the application classloader
 *    plus every live thread's contextClassLoader, snapshots every
 *    `(loaderClassName, dexPath, cookieIdentity)` tuple on the first
 *    [scan] call, and diffs against that snapshot on every subsequent
 *    call.
 *  - **Channel (b) — `/proc/self/maps` named-anon scan.** Reads
 *    `/proc/self/maps`, isolates `[anon:dalvik-...]` regions, and
 *    classifies each. New `[anon:dalvik-DEX data]` regions
 *    post-baseline are the canonical InMemoryDexClassLoader /
 *    DexClassLoader extraction signature on Android 14+.
 *
 * Channel (a) catches disk-backed `DexClassLoader` payloads that
 * channel (b) might miss when the named-anon label encodes the
 * file path. Channel (b) catches `InMemoryDexClassLoader` even
 * when the loader chain has been tampered with via reflection to
 * hide the new element.
 *
 * Failure modes:
 *  - Reflection on `BaseDexClassLoader` internals throws on an OEM
 *    fork that renamed the fields. The helper catches the throw
 *    and degrades channel (a) to "unavailable" without affecting
 *    channel (b).
 *  - [NativeBridge] not loaded → channel (b) skipped; channel (a)
 *    still runs.
 *  - First [scan] captures the baseline AND emits a per-region
 *    `unattributable_dex_at_baseline` finding for any pre-baseline
 *    suspicious state (the answer to the Zygisk timing gap).
 */
internal object DexInjection {

    private const val TAG = "DeviceIntelligence.DexInjection"

    internal const val KIND_CLASSLOADER_ADDED = "dex_classloader_added"
    internal const val KIND_PATH_OUTSIDE_APK = "dex_path_outside_apk"
    internal const val KIND_IN_MEMORY_LOADER = "dex_in_memory_loader_injected"
    internal const val KIND_ANON_MAPPING = "dex_in_anonymous_mapping"

    /**
     * Emitted when the **first observed** snapshot already contains
     * a `[anon:dalvik-DEX data]` region or an in-memory DEX loader
     * not attributable to the APK split set. By definition we
     * can't tell whether the injection happened legitimately
     * pre-process-start or as a real Zygisk pre-baseline tamper —
     * but it's a strong correlator a backend can pivot on across
     * many devices. MEDIUM severity, informational.
     */
    internal const val KIND_UNATTRIBUTABLE_AT_BASELINE = "unattributable_dex_at_baseline"

    /**
     * Identity tuple captured per dex element. `cookieIdentity` is
     * `System.identityHashCode(mCookie)` — stable for the lifetime
     * of the cookie object inside ART, but cheap to compute and not
     * sensitive to the cookie's actual contents (which vary across
     * Android versions: `long[]` on older builds, `Object[]`
     * containing `DexFile`-internal handles on newer ones).
     */
    internal data class DexElementSnapshot(
        val loaderClassName: String,
        val dexPath: String?,
        val cookieIdentity: Int,
    )

    @Volatile
    private var loaderBaseline: Set<DexElementSnapshot>? = null

    /**
     * Stored per-region as `(label, addressRange)` tuples.
     * Keying on label alone collapses every
     * `[anon:dalvik-DEX data]` region into a single bucket
     * (the label is identical for all in-memory DEX extractions
     * on Android 14+), so multiple injected regions would diff
     * to "no change" against a baseline containing any one of
     * them. Address range stays stable for the lifetime of the
     * mapping — ART picks it via mmap and never moves it — so
     * tuples are a stable identity per region.
     */
    @Volatile
    private var anonRegionBaseline: Set<Pair<String, String>>? = null

    private val baselineLock = Any()

    /**
     * Runs both channels and returns the combined findings list.
     *
     * Idempotent across repeated calls — the per-channel baseline
     * snapshots are captured on the first call (regardless of which
     * channel runs first) and reused for subsequent diffs.
     *
     * Always re-runs both channels on every invocation; DEX
     * injection is a live signal that can change mid-process.
     * Caller ([RuntimeEnvironmentDetector.doLiveEvaluate]) is
     * responsible for *not* caching the result.
     */
    internal fun scan(ctx: DetectorContext): List<Finding> {
        val findings = ArrayList<Finding>(4)

        // Channel (a) — ClassLoader chain. Pure Kotlin; runs even
        // when the native bridge is unavailable.
        val loaderResult = runCatching { evaluateLoaderChain(ctx.applicationContext) }
            .onFailure { Log.w(TAG, "channel (a) reflection threw", it) }
            .getOrNull()
        if (loaderResult != null) findings += loaderResult

        // Channel (b) — named-anon DEX regions in /proc/self/maps.
        // Skipped when the native bridge can't read maps. Failures
        // are degraded to "unavailable" rather than escalated.
        if (ctx.nativeReady) {
            val anonResult = runCatching { evaluateAnonMappings(ctx.applicationContext) }
                .onFailure { Log.w(TAG, "channel (b) maps scan threw", it) }
                .getOrNull()
            if (anonResult != null) findings += anonResult
        }

        Log.i(TAG, "ran: ${findings.size} finding(s)")
        return findings
    }

    // ---- Channel (a) ----------------------------------------------------

    private fun evaluateLoaderChain(appCtx: Context): List<Finding> {
        val current = walkLoaderChain(appCtx.classLoader)
        val baseline = synchronized(baselineLock) {
            loaderBaseline ?: current.also { loaderBaseline = it }
        }
        // First evaluate — the snapshot IS the clean baseline, so
        // by definition nothing is "new" yet.
        if (baseline === current) return emptyList()

        val added = current - baseline
        if (added.isEmpty()) return emptyList()

        val ai = appCtx.applicationInfo
        val out = ArrayList<Finding>(added.size)
        for (entry in added) {
            val path = entry.dexPath
            val (kind, severity, message) = when {
                path.isNullOrEmpty() -> Triple(
                    KIND_IN_MEMORY_LOADER,
                    Severity.HIGH,
                    "New in-memory DEX classloader added post-baseline (no file path)",
                )
                !pathIsAllowed(path, ai) -> Triple(
                    KIND_PATH_OUTSIDE_APK,
                    Severity.HIGH,
                    "New DEX element loaded from a path outside the APK / dalvik-cache",
                )
                else -> Triple(
                    KIND_CLASSLOADER_ADDED,
                    Severity.MEDIUM,
                    "New DEX classloader entry appeared post-baseline",
                )
            }
            out += Finding(
                kind = kind,
                severity = severity,
                subject = ai.packageName.orEmpty(),
                message = message,
                details = mapOf(
                    "loader" to entry.loaderClassName,
                    "dex_path" to (path ?: "<null>"),
                    "cookie_id" to entry.cookieIdentity.toString(),
                ),
            )
        }
        return out
    }

    /**
     * Multi-root ClassLoader traversal.
     *
     * The naive `start.parent` walk only visits ancestors of the
     * application's primary classloader, but injected
     * `BaseDexClassLoader` instances are typically CHILDREN of the
     * app loader (their `parent` field points at the app loader,
     * not the other way around). Walking up from the app loader
     * never visits them.
     *
     * Java has no built-in "list every ClassLoader in the JVM"
     * API. The workable approximation is a multi-root sweep:
     *
     *  1. Start from the supplied [start] (the application
     *     classloader) and walk its parent chain.
     *  2. Enumerate every live thread via
     *     [Thread.getAllStackTraces], read each one's
     *     `contextClassLoader`, and walk those parent chains too.
     *
     * Attackers commonly create a worker thread whose
     * `contextClassLoader` is the injected loader itself (it's
     * the easiest way to make the injected DEX's classes
     * resolvable from the worker's reflection calls). Even when
     * they don't, framework-spawned threads sometimes inherit a
     * context loader that *does* point at the injected one
     * (e.g. AsyncTask threads, RxJava workers).
     *
     * This still misses purely-locally-referenced loaders — an
     * attacker who just stores the loader in a static field and
     * never sets it as anyone's context loader can hide. For that
     * case the only reliable detection is JNI enumeration of
     * ART's `ClassLinker::class_loaders_` weak list, tracked as a
     * future improvement under CTF Flag 1's roadmap. But the
     * common case is caught by this multi-root traversal.
     *
     * Identity-keyed dedup: many threads share the same context
     * loader, so we walk each unique loader at most once.
     */
    private fun walkLoaderChain(start: ClassLoader?): Set<DexElementSnapshot> {
        val out = LinkedHashSet<DexElementSnapshot>()
        val visited = java.util.IdentityHashMap<ClassLoader, Unit>()

        fun walkFrom(root: ClassLoader?) {
            var loader: ClassLoader? = root
            // Hard cap to avoid infinite walks if something cyclical
            // sneaks into the parent chain (shouldn't happen, but the
            // detector must never wedge the collect call).
            var hops = 0
            while (loader != null && hops < 32) {
                if (visited.containsKey(loader)) return
                visited[loader] = Unit
                if (loader is BaseDexClassLoader) {
                    runCatching { extractDexElements(loader, out) }
                        .onFailure { Log.w(TAG, "extractDexElements failed for $loader", it) }
                }
                loader = loader.parent
                hops++
            }
        }

        walkFrom(start)

        // Thread-context-loader sweep. Wrapped in runCatching so a
        // hardened SecurityManager (rare on Android, but possible
        // under some MDM profiles) can't break the detector.
        runCatching {
            for (thread in Thread.getAllStackTraces().keys) {
                val ctxLoader = runCatching { thread.contextClassLoader }.getOrNull()
                walkFrom(ctxLoader)
            }
        }.onFailure { Log.w(TAG, "thread context loader sweep failed", it) }

        return out
    }

    private fun extractDexElements(loader: BaseDexClassLoader, sink: MutableSet<DexElementSnapshot>) {
        val pathListField = BaseDexClassLoader::class.java.getDeclaredField("pathList")
            .apply { isAccessible = true }
        val pathList = pathListField.get(loader) ?: return
        val dexElementsField = pathList.javaClass.getDeclaredField("dexElements")
            .apply { isAccessible = true }
        val dexElements = dexElementsField.get(pathList) as? Array<*> ?: return

        for (element in dexElements) {
            if (element == null) continue
            val dexFileField = runCatching {
                element.javaClass.getDeclaredField("dexFile").apply { isAccessible = true }
            }.getOrNull() ?: continue
            val dexFile = dexFileField.get(element) ?: continue

            val mFileNameField = runCatching {
                dexFile.javaClass.getDeclaredField("mFileName").apply { isAccessible = true }
            }.getOrNull()
            val mCookieField = runCatching {
                dexFile.javaClass.getDeclaredField("mCookie").apply { isAccessible = true }
            }.getOrNull()

            val path = mFileNameField?.get(dexFile) as? String
            val cookie = mCookieField?.get(dexFile)
            sink += DexElementSnapshot(
                loaderClassName = loader.javaClass.name,
                dexPath = path?.takeIf { it.isNotEmpty() },
                cookieIdentity = if (cookie != null) System.identityHashCode(cookie) else 0,
            )
        }
    }

    // ---- Channel (b) ----------------------------------------------------

    private fun evaluateAnonMappings(appCtx: Context): List<Finding> {
        val maps = NativeBridge.procSelfMaps() ?: return emptyList()
        val regions = MapsParser.scanDalvikAnonRegions(maps)
        if (regions.isEmpty()) return emptyList()

        val ai = appCtx.applicationInfo

        // First-evaluate snapshot path. We capture the baseline
        // tuple set here AND emit any
        // `unattributable_dex_at_baseline` findings if the very
        // first observation already contains suspicious regions.
        // This is the answer to the Zygisk / early-LSPosed timing
        // gap: we can't reach back in time and detect a pre-process
        // injection, but we CAN flag that the baseline was already
        // dirty when we first looked.
        var freshlySnapshotted = false
        val baseline = synchronized(baselineLock) {
            anonRegionBaseline ?: regions.mapTo(LinkedHashSet()) {
                it.label to it.addressRange
            }.also {
                anonRegionBaseline = it
                freshlySnapshotted = true
            }
        }

        if (freshlySnapshotted) {
            val baselineFindings = ArrayList<Finding>(0)
            for (region in regions) {
                val verdict = classifyDalvikRegion(region, ai)
                if (verdict.kind == DalvikRegionKind.IN_MEMORY ||
                    verdict.kind == DalvikRegionKind.IN_MEMORY_UNATTRIBUTED ||
                    verdict.kind == DalvikRegionKind.FOREIGN_PATH) {
                    baselineFindings += Finding(
                        kind = KIND_UNATTRIBUTABLE_AT_BASELINE,
                        severity = Severity.MEDIUM,
                        subject = ai.packageName.orEmpty(),
                        message = "First-observed snapshot already contained an in-memory DEX " +
                            "region (pre-baseline injection or legitimate framework preload — " +
                            "backend should correlate)",
                        details = mapOf(
                            "address_range" to region.addressRange,
                            "label" to region.label,
                            "verdict" to verdict.kind.name,
                            "source" to (verdict.source ?: "<unattributed>"),
                        ),
                    )
                }
            }
            return baselineFindings
        }

        val out = ArrayList<Finding>(2)
        for (region in regions) {
            val key = region.label to region.addressRange
            if (key in baseline) continue
            val verdict = classifyDalvikRegion(region, ai)
            when (verdict.kind) {
                DalvikRegionKind.IN_MEMORY -> out += Finding(
                    kind = KIND_ANON_MAPPING,
                    severity = Severity.HIGH,
                    subject = ai.packageName.orEmpty(),
                    message = "InMemoryDexClassLoader-style DEX region appeared post-baseline",
                    details = mapOf(
                        "address_range" to region.addressRange,
                        "label" to region.label,
                        "source" to (verdict.source ?: "<unknown>"),
                    ),
                )
                DalvikRegionKind.IN_MEMORY_UNATTRIBUTED -> out += Finding(
                    kind = KIND_ANON_MAPPING,
                    severity = Severity.HIGH,
                    subject = ai.packageName.orEmpty(),
                    message = "New `[anon:dalvik-DEX data]` region appeared post-baseline " +
                        "(InMemoryDexClassLoader / DexClassLoader extraction)",
                    details = mapOf(
                        "address_range" to region.addressRange,
                        "label" to region.label,
                        "source" to "<unattributed>",
                    ),
                )
                DalvikRegionKind.FOREIGN_PATH -> out += Finding(
                    kind = KIND_ANON_MAPPING,
                    severity = Severity.HIGH,
                    subject = ai.packageName.orEmpty(),
                    message = "DEX region extracted from a path outside the APK / dalvik-cache",
                    details = mapOf(
                        "address_range" to region.addressRange,
                        "label" to region.label,
                        "source" to (verdict.source ?: "<unknown>"),
                    ),
                )
                // OWN_APK / SYSTEM / NON_DEX / UNKNOWN — clean signal,
                // even if it appeared post-baseline (ART legitimately
                // mints new dalvik-anon regions for JIT cache,
                // zygote-claimed pages, freshly-extracted classes from
                // splits, etc.). The high-confidence channel is
                // IN_MEMORY / IN_MEMORY_UNATTRIBUTED / FOREIGN_PATH only.
                else -> Unit
            }
        }
        return out
    }

    // ---- Path classification --------------------------------------------

    /**
     * True when [path] points at a DEX source the SDK considers
     * legitimate for this app: its own APK or splits, framework or
     * apex jars, or the dalvik-cache. Anything else (including
     * `/data/local/tmp/`, foreign packages' data dirs, or unknown
     * non-system paths) returns false.
     */
    internal fun pathIsAllowed(path: String, ai: ApplicationInfo): Boolean {
        if (path.isEmpty()) return false
        // Direct match against the APK split set first — exact
        // string compare is the strongest signal we can get.
        if (path == ai.sourceDir) return true
        if (path == ai.publicSourceDir) return true
        ai.splitSourceDirs?.forEach { if (path == it) return true }
        ai.splitPublicSourceDirs?.forEach { if (path == it) return true }

        // System trees that ART legitimately loads bytecode from.
        if (path.startsWith("/system/framework/")) return true
        if (path.startsWith("/system/app/")) return true
        if (path.startsWith("/system/priv-app/")) return true
        if (path.startsWith("/system_ext/")) return true
        if (path.startsWith("/apex/")) return true
        if (path.startsWith("/product/")) return true
        if (path.startsWith("/vendor/")) return true
        if (path.startsWith("/data/dalvik-cache/")) return true

        // Last-ditch fuzzy match: AGP can install a split into a
        // path the ApplicationInfo arrays don't surface (e.g.
        // dynamic feature modules dropped under
        // `/data/app/<pkg>-<hash>/split_name.apk`). Accept any
        // /data/app/.../<pkg>... path as legitimate; the
        // ClassLoader-added-but-known-path case is downgraded to
        // MEDIUM regardless via [evaluateLoaderChain].
        val pkg = ai.packageName.orEmpty()
        if (pkg.isNotEmpty() && path.startsWith("/data/app/") && pathContainsPackageComponent(path, pkg)) {
            return true
        }
        return false
    }

    private fun pathContainsPackageComponent(path: String, pkg: String): Boolean {
        if (pkg.isEmpty()) return false
        var idx = 0
        while (true) {
            val hit = path.indexOf(pkg, idx)
            if (hit < 0) return false
            val leftOk = hit == 0 || path[hit - 1] == '/' || path[hit - 1] == '-'
            val rightIdx = hit + pkg.length
            val rightOk = rightIdx == path.length ||
                path[rightIdx] == '/' || path[rightIdx] == '-' || path[rightIdx] == '.'
            if (leftOk && rightOk) return true
            idx = hit + 1
        }
    }

    internal enum class DalvikRegionKind {
        /**
         * `extracted in memory from <buffer>` — older Android
         * releases (≤ 13) tagged `InMemoryDexClassLoader` regions
         * with the originating source verbatim, and `<buffer>` was
         * the literal placeholder for ByteBuffer-backed loads.
         */
        IN_MEMORY,
        /**
         * `dalvik-DEX data` — Android 14+ collapsed all
         * InMemoryDexClassLoader / DexClassLoader extraction
         * regions to this single label, dropping the source
         * attribution. We can't tell whether the bytes came from
         * a buffer or a foreign disk path; we just know it's
         * in-memory DEX content sitting in the address space.
         * Treated as suspicious-if-new at the same severity as
         * [IN_MEMORY].
         */
        IN_MEMORY_UNATTRIBUTED,
        /** `extracted in memory from <some-path>` where the path is not the app's own APK or a system tree. */
        FOREIGN_PATH,
        /** `extracted in memory from <app's-own-APK or system tree>`. */
        OWN_APK,
        /** Anything that isn't a DEX-extraction region: jit-code-cache, zygote-claimed pages, etc. */
        NON_DEX,
        /** Region label didn't parse cleanly — we degrade to "no signal" rather than false-positive. */
        UNKNOWN,
    }

    internal data class DalvikRegionVerdict(val kind: DalvikRegionKind, val source: String?)

    /**
     * Classifies one `[anon:dalvik-...]` region by what its label
     * says about the DEX source. Two label families exist in the
     * wild:
     *
     * **Android 14+ (and our Pixel 6 Pro reference device on
     * Android 16):** ART collapses every InMemoryDexClassLoader
     * and DexClassLoader extraction into a single anonymous
     * mapping labelled exactly `[anon:dalvik-DEX data]`. There is
     * no source attribution. Verdict: [DalvikRegionKind.IN_MEMORY_UNATTRIBUTED].
     * If new since baseline = strong tamper signal.
     *
     * **Older Android (≤ 13):** label format is
     * `anon:dalvik-classes.dex extracted in memory from <source>`,
     * where `<source>` is either `<buffer>` (ByteBuffer-backed
     * load) or a file path. Verdict depends on whether the path
     * is attributable to the app's APK split set or a system
     * tree.
     *
     * Plus the always-benign families (jit-code-cache, zygote
     * spaces, LinearAlloc, boot-image art files, sentinel pages).
     */
    internal fun classifyDalvikRegion(
        region: MapsParser.DalvikAnonRegion,
        ai: ApplicationInfo,
    ): DalvikRegionVerdict {
        // region.label is the substring INSIDE the brackets, e.g.
        // "anon:dalvik-classes.dex extracted in memory from <path>".
        // Strip the "anon:dalvik-" prefix; if it's missing the
        // caller filtered wrong and we degrade to UNKNOWN.
        val payload = region.label.removePrefix("anon:dalvik-")
        if (payload === region.label) return DalvikRegionVerdict(DalvikRegionKind.UNKNOWN, null)

        // Android 14+ short form. Exact-match the literal label
        // (the ART change that introduced this format does not
        // include any suffix or address detail). Verified on
        // Pixel 6 Pro / Android 16 stock with InMemoryDexClassLoader
        // + ByteBuffer.wrap injection: produces exactly
        // `[anon:dalvik-DEX data]` for every injected DEX,
        // regardless of whether the source was a buffer or a disk
        // path.
        if (payload == "DEX data") {
            return DalvikRegionVerdict(DalvikRegionKind.IN_MEMORY_UNATTRIBUTED, null)
        }

        // Boot image .art mappings carry the boot path as the
        // payload — these always exist on every Android process
        // (they're how the boot framework is mapped into Zygote
        // children). Filter explicitly so we never mistake them
        // for DEX content.
        if (payload.endsWith(".art") || payload.startsWith("/system/framework/boot")) {
            return DalvikRegionVerdict(DalvikRegionKind.NON_DEX, null)
        }

        val key = "extracted in memory from "
        val ix = payload.indexOf(key)
        if (ix < 0) {
            // Not an extraction region — it's a JIT/zygote/heap span.
            return DalvikRegionVerdict(DalvikRegionKind.NON_DEX, null)
        }
        val source = payload.substring(ix + key.length).trim()
        return when {
            source.startsWith("<") && source.endsWith(">") ->
                DalvikRegionVerdict(DalvikRegionKind.IN_MEMORY, source)
            source.startsWith("/system/") ||
                source.startsWith("/apex/") ||
                source.startsWith("/product/") ||
                source.startsWith("/vendor/") ->
                DalvikRegionVerdict(DalvikRegionKind.OWN_APK, source)
            pathIsAllowed(source, ai) ->
                DalvikRegionVerdict(DalvikRegionKind.OWN_APK, source)
            else ->
                DalvikRegionVerdict(DalvikRegionKind.FOREIGN_PATH, source)
        }
    }

    /** Test-only: drop the cached baselines so the next [evaluate] re-snapshots. */
    internal fun resetForTest() {
        synchronized(baselineLock) {
            loaderBaseline = null
            anonRegionBaseline = null
        }
    }
}
