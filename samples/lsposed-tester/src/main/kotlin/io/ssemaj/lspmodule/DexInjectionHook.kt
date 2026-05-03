package io.ssemaj.lspmodule

import android.app.Application
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import dalvik.system.InMemoryDexClassLoader
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.nio.ByteBuffer

/**
 * CTF Flag 1 — runtime DEX injection driven by a real LSPosed
 * module. Sister entry point to [MainHook] (which validates the
 * StackGuard / StackWatchdog detectors). Declared in
 * `assets/xposed_init` alongside MainHook so the LSPosed
 * framework instantiates both per target process.
 *
 * What this exercises:
 *   - **Channel (b) — InMemoryDexClassLoader.** The baked
 *     [Flag1Payload.BAKED_DEX] bytes are wrapped in a
 *     [ByteBuffer] and handed to [InMemoryDexClassLoader],
 *     which forces ART to mint an
 *     `[anon:dalvik-classes.dex extracted in memory from
 *     DEX data]` mapping. The [DexInjection] helper inside
 *     `runtime.environment` classifies it as IN_MEMORY_UNATTRIBUTED
 *     and emits `dex_in_anonymous_mapping`.
 *   - **Channel (a) — DexClassLoader from a foreign path.**
 *     Optional second-half: if a `payload.dex` has been pushed
 *     to `/data/local/tmp/flag1-payload.dex`, this hook also
 *     loads it via `DexClassLoader`, which adds a new
 *     [dalvik.system.BaseDexClassLoader] to the chain whose
 *     `mFileName` points outside the APK split set. Should emit
 *     `dex_path_outside_apk`.
 *
 * Timing strategy (load-bearing):
 *   - LSPosed's `handleLoadPackage` runs at target-app classload
 *     time — BEFORE [DeviceIntelligenceInitProvider]'s pre-warm
 *     coroutine has had a chance to run. If we injected the DEX
 *     here synchronously, the detector's first-evaluate snapshot
 *     would include our injection as part of the clean baseline
 *     and silently miss it.
 *   - Instead we schedule a worker thread that:
 *       1. Forces a synchronous `DeviceIntelligence.collectBlocking()`
 *          to lock in a known-clean baseline (this triggers the
 *          detector's first evaluate before any tamper). We use
 *          `awaitPrewarm` semantics indirectly: collectBlocking is
 *          re-entrant against the prewarm and produces a fresh
 *          report either way, and the detector's snapshot is taken
 *          on whichever evaluate() runs first.
 *       2. Injects the DEX via InMemoryDexClassLoader (and
 *          optionally DexClassLoader).
 *       3. Forces a second `collectBlocking()` and logs the
 *          `runtime.dex` findings — these are the post-tamper
 *          deltas the detector should be reporting.
 *
 * Capture criteria — Flag 1 is captured (via this LSPosed path)
 * when the post-tamper findings list contains at least one of:
 *   - `dex_in_memory_loader_injected`
 *   - `dex_in_anonymous_mapping`
 *   - `dex_path_outside_apk` (only if the optional disk-backed
 *     payload was pushed)
 *
 * Look for the result in `logcat -s DI-LSPDexHook` (or in
 * LSPosed's own log under `/data/adb/lspd/log/`).
 */
class DexInjectionHook : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PACKAGE) return
        XposedBridge.log("[$TAG] scheduled DEX-injection harness for $TARGET_PACKAGE")
        Log.i(TAG, "scheduled DEX-injection harness for $TARGET_PACKAGE")

        // Wait long enough for Application.onCreate() to install
        // ContentProviders (including DeviceIntelligenceInitProvider)
        // and for the prewarm coroutine to land its first
        // evaluate(). 2.5 s is comfortable on a Pixel 6 Pro; bump
        // up if running on slower hardware. The exact value is not
        // load-bearing — Step 1 below also forces a fresh evaluate
        // to lock in the baseline regardless of prewarm timing.
        Handler(Looper.getMainLooper()).postDelayed(
            { runHarness(lpparam) },
            POST_LAUNCH_DELAY_MS,
        )
    }

    private fun runHarness(lpparam: XC_LoadPackage.LoadPackageParam) {
        // Run on a dedicated worker so we never block the host
        // app's main thread with collectBlocking calls.
        Thread({ executeOnWorker(lpparam) }, "$TAG-worker").start()
    }

    private fun executeOnWorker(lpparam: XC_LoadPackage.LoadPackageParam) {
        try {
            val ctx = currentApplicationContext()
            if (ctx == null) {
                XposedBridge.log("[$TAG] no Application yet — bailing")
                return
            }

            val diInstance = resolveDeviceIntelligenceInstance(lpparam)
            if (diInstance == null) {
                XposedBridge.log("[$TAG] could not resolve DeviceIntelligence singleton — wrong build?")
                return
            }

            // ---- Step 1: lock in baseline ---------------------------------
            XposedBridge.log("[$TAG] step 1: baseline collect (locks DexInjection helper snapshot)")
            val baselineKinds = collectRuntimeDexKinds(diInstance, ctx, "baseline")
            if (baselineKinds.isNotEmpty()) {
                XposedBridge.log(
                    "[$TAG] WARNING: baseline already non-clean — " +
                        "${baselineKinds.size} dex-injection finding(s): $baselineKinds",
                )
                // Continue anyway; the test will compare delta.
            }

            // ---- Step 2: inject DEX via InMemoryDexClassLoader ------------
            XposedBridge.log("[$TAG] step 2a: InMemoryDexClassLoader injection (channel b)")
            try {
                val parent = lpparam.classLoader
                val buffer = ByteBuffer.wrap(Flag1Payload.BAKED_DEX)
                val loader = InMemoryDexClassLoader(buffer, parent)
                val cls = runCatching { loader.loadClass("Payload") }.getOrNull()
                XposedBridge.log("[$TAG] in-memory loader=$loader resolved=${cls?.name}")
            } catch (t: Throwable) {
                XposedBridge.log("[$TAG] InMemoryDexClassLoader injection failed: $t")
            }

            // ---- Step 2b: optional disk-backed DexClassLoader -------------
            val tmpPayload = File("/data/local/tmp/flag1-payload.dex")
            if (tmpPayload.exists() && tmpPayload.canRead()) {
                XposedBridge.log("[$TAG] step 2b: DexClassLoader from ${tmpPayload.absolutePath} (channel a)")
                try {
                    val cacheDir = ctx.codeCacheDir.absolutePath
                    val DexClassLoader = Class.forName("dalvik.system.DexClassLoader")
                    val ctor = DexClassLoader.getConstructor(
                        String::class.java, String::class.java,
                        String::class.java, ClassLoader::class.java,
                    )
                    val diskLoader = ctor.newInstance(
                        tmpPayload.absolutePath, cacheDir, null, lpparam.classLoader,
                    ) as ClassLoader
                    val cls = runCatching { diskLoader.loadClass("Payload") }.getOrNull()
                    XposedBridge.log("[$TAG] disk loader=$diskLoader resolved=${cls?.name}")
                } catch (t: Throwable) {
                    XposedBridge.log("[$TAG] DexClassLoader injection failed: $t")
                }
            } else {
                XposedBridge.log(
                    "[$TAG] step 2b skipped — no /data/local/tmp/flag1-payload.dex " +
                        "(push it via adb to also exercise channel a)",
                )
            }

            // ---- Step 3: verify -------------------------------------------
            XposedBridge.log("[$TAG] step 3: post-tamper collect")
            val postKinds = collectRuntimeDexKinds(diInstance, ctx, "post-tamper")

            val newKinds = postKinds - baselineKinds.toSet()
            val captured = newKinds.any { kind ->
                kind == "dex_in_memory_loader_injected" ||
                    kind == "dex_in_anonymous_mapping" ||
                    kind == "dex_path_outside_apk"
            }
            if (captured) {
                XposedBridge.log("[$TAG] FLAG CAPTURED — post-tamper delta: $newKinds")
                Log.w(TAG, "FLAG CAPTURED — post-tamper delta: $newKinds")
            } else {
                XposedBridge.log(
                    "[$TAG] FLAG NOT CAPTURED — baseline=$baselineKinds " +
                        "post=$postKinds delta=$newKinds",
                )
                Log.w(
                    TAG,
                    "FLAG NOT CAPTURED — baseline=$baselineKinds post=$postKinds delta=$newKinds",
                )
            }
        } catch (t: Throwable) {
            XposedBridge.log("[$TAG] harness threw: $t")
            Log.e(TAG, "harness threw", t)
        }
    }

    /**
     * Resolves the `DeviceIntelligence` Kotlin object's INSTANCE
     * field via the target process's classloader. Reflective
     * because this module deliberately has no compile-time
     * dependency on the library — the real type isn't on our
     * classpath.
     */
    private fun resolveDeviceIntelligenceInstance(lpparam: XC_LoadPackage.LoadPackageParam): Any? {
        return runCatching {
            val cls = XposedHelpers.findClass(DI_CLASS, lpparam.classLoader)
            XposedHelpers.getStaticObjectField(cls, "INSTANCE")
        }.getOrNull()
    }

    /**
     * Reflective `ActivityThread.currentApplication()` lookup —
     * the canonical way to get hold of the host Application from
     * code that has no `Context` of its own. Both `ActivityThread`
     * and `AndroidAppHelper` are hidden framework classes excluded
     * from the public SDK stub, so we go through `Class.forName`
     * + a public-but-undocumented static method. LSPosed-style
     * hidden-API access is granted to the module process by the
     * framework itself, so this resolves at runtime.
     */
    private fun currentApplicationContext(): Context? = runCatching {
        val cls = Class.forName("android.app.ActivityThread")
        val method = cls.getDeclaredMethod("currentApplication").apply { isAccessible = true }
        (method.invoke(null) as? Application)?.applicationContext
    }.onFailure { XposedBridge.log("[$TAG] currentApplication lookup failed: $it") }
        .getOrNull()

    /**
     * Calls `DeviceIntelligence.collectBlocking(ctx)` reflectively,
     * locates the `runtime.environment` detector report, and
     * returns just the DEX-injection-related finding kinds (the
     * ones [DexInjection] emits via the runtime.environment
     * helper). Other runtime.environment kinds (hook_framework_present,
     * rwx_memory_mapping, debugger_attached, etc.) are filtered
     * out so the FLAG CAPTURED / NOT CAPTURED verdict is purely
     * about DEX injection.
     */
    private fun collectRuntimeDexKinds(
        diInstance: Any,
        ctx: Context,
        phase: String,
    ): List<String> {
        val report = runCatching {
            XposedHelpers.callMethod(diInstance, "collectBlocking", ctx)
        }.onFailure { XposedBridge.log("[$TAG $phase] collectBlocking threw: $it") }
            .getOrNull() ?: return emptyList()
        val detectors = runCatching { XposedHelpers.callMethod(report, "getDetectors") as List<*> }
            .getOrNull() ?: return emptyList()
        for (d in detectors) {
            if (d == null) continue
            val id = runCatching { XposedHelpers.callMethod(d, "getId") as? String }.getOrNull()
            if (id != "runtime.environment") continue
            val findings = runCatching {
                XposedHelpers.callMethod(d, "getFindings") as? List<*>
            }.getOrNull().orEmpty()
            val kinds = ArrayList<String>(findings.size)
            for (f in findings) {
                if (f == null) continue
                val kind = runCatching { XposedHelpers.callMethod(f, "getKind") as? String }
                    .getOrNull() ?: continue
                if (kind !in DEX_INJECTION_KINDS) continue
                val message = runCatching { XposedHelpers.callMethod(f, "getMessage") as? String }
                    .getOrNull().orEmpty()
                XposedBridge.log("[$TAG $phase]   finding kind=$kind message=\"$message\"")
                kinds += kind
            }
            XposedBridge.log("[$TAG $phase] runtime.environment dex-injection findings=${kinds.size}")
            return kinds
        }
        XposedBridge.log("[$TAG $phase] runtime.environment detector not present in report — wrong build?")
        return emptyList()
    }

    private companion object {
        const val TAG = "DI-LSPDexHook"
        const val TARGET_PACKAGE = "io.ssemaj.sample"
        const val DI_CLASS = "io.ssemaj.deviceintelligence.DeviceIntelligence"
        const val POST_LAUNCH_DELAY_MS = 2500L

        /**
         * The exact set of finding kinds emitted by [DexInjection]
         * inside `runtime.environment`. We filter to these for the
         * FLAG CAPTURED verdict so unrelated runtime.environment
         * findings (hook_framework_present, rwx_memory_mapping,
         * debugger_attached, ...) don't pollute the result.
         */
        val DEX_INJECTION_KINDS = setOf(
            "dex_classloader_added",
            "dex_path_outside_apk",
            "dex_in_memory_loader_injected",
            "dex_in_anonymous_mapping",
            "unattributable_dex_at_baseline",
        )
    }
}
