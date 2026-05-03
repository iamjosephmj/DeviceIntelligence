package io.ssemaj.lspmodule

import android.app.Application
import android.content.Context
import android.util.Log
import dalvik.system.InMemoryDexClassLoader
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import java.io.File
import java.nio.ByteBuffer

/**
 * CTF Flag 1 — pre-baseline DEX injection.
 *
 * **Purpose: simulate a Zygisk module's timing without needing a
 * Magisk module flash cycle.** Zygisk's `postAppSpecialize` runs
 * BEFORE Android calls [Application.onCreate], which means the
 * injection happens BEFORE [DeviceIntelligenceInitProvider]
 * spawns the pre-warm coroutine that triggers
 * [DexInjection]'s first scan inside [RuntimeEnvironmentDetector].
 * The helper's snapshot therefore captures the loader chain WITH
 * the foreign DEX already in it, masking the injection as part of
 * the clean baseline.
 *
 * LSPosed's `handleLoadPackage` runs in the same lifecycle
 * window — after the host app's classloader is built but before
 * `Application.onCreate`. By injecting **synchronously** here
 * (not via the `postDelayed` worker that [DexInjectionHook]
 * uses), we reproduce Zygisk's pre-baseline timing exactly. No
 * native code, no Magisk module, no reboot.
 *
 * Expected outcome (the thing we want to learn):
 *   - **Channel (a)** — the loader-chain diff — SHOULD MISS this
 *     injection. The new BaseDexClassLoader is in the chain
 *     before the snapshot is taken, so the snapshot includes it
 *     and there is nothing "new" to flag on subsequent collects.
 *     This is a real detector gap.
 *   - **Channel (b)** — the `[anon:dalvik-...]` named-region
 *     scan — depends on timing of when ART mints the anon
 *     region for the in-memory DEX vs when the maps snapshot is
 *     taken. The maps snapshot in [DexInjection] is also captured
 *     on first scan, so if ART mints the region
 *     before the snapshot, channel (b) misses it too. If ART
 *     defers minting until the first class load, channel (b)
 *     catches it (because we trigger the load reflectively here
 *     after the snapshot).
 *
 * If both channels miss, the detector needs a third signal: an
 * `unattributable_dex_at_baseline` finding emitted when the
 * first-observed snapshot ALREADY contains a DEX element whose
 * path is null or outside the APK split set. That finding is
 * informational — by definition we can't tell whether the
 * injection happened pre-process-start (legitimate Zygote
 * preloading) or post-process-start-but-pre-our-snapshot (real
 * tamper) — but it's a strong signal a backend can correlate
 * across many devices to identify outliers.
 *
 * To run: enable both [MainHook], [DexInjectionHook], AND this
 * hook in the LSPosed scope picker. Compare the
 * `FLAG CAPTURED` / `FLAG NOT CAPTURED` outcomes between the
 * two harnesses. If [DexInjectionHook] captures but this one
 * does not, the timing-gap hypothesis is confirmed and the next
 * step is the detector fix.
 *
 * Tag: `DI-LSPEarlyHook`.
 */
class EarlyDexInjectionHook : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != TARGET_PACKAGE) return
        XposedBridge.log("[$TAG] pre-baseline DEX injection (synchronous, in handleLoadPackage)")
        Log.i(TAG, "pre-baseline DEX injection (synchronous, in handleLoadPackage)")

        try {
            // ---- Inject in-memory DEX, synchronously ----------------------
            // This runs BEFORE DeviceIntelligenceInitProvider's prewarm
            // coroutine has had a chance to execute. The new
            // BaseDexClassLoader is in the chain when the detector's
            // first-evaluate snapshot is taken, so channel (a)'s diff
            // should report nothing.
            val parent = lpparam.classLoader
            val buffer = ByteBuffer.wrap(Flag1Payload.BAKED_DEX)
            val loader = InMemoryDexClassLoader(buffer, parent)

            // Force ART to actually mint the anon region by resolving a
            // class out of the loader. Without this, the bytes sit in
            // the ByteBuffer's heap allocation and don't show up in
            // /proc/self/maps as a `dalvik-classes.dex extracted in
            // memory from <buffer>` region. This is the moment that
            // *might* race against channel (b)'s baseline snapshot.
            val cls = runCatching { loader.loadClass("Payload") }.getOrNull()
            XposedBridge.log("[$TAG] in-memory loader=$loader resolved=${cls?.name}")

            // ---- Optional disk-backed loader, also pre-baseline ----------
            val tmpPayload = File("/data/local/tmp/flag1-payload.dex")
            if (tmpPayload.exists() && tmpPayload.canRead()) {
                try {
                    val DexClassLoader = Class.forName("dalvik.system.DexClassLoader")
                    val ctor = DexClassLoader.getConstructor(
                        String::class.java, String::class.java,
                        String::class.java, ClassLoader::class.java,
                    )
                    // Use /data/local/tmp as the optDir as well — the
                    // app's codeCacheDir isn't reliably available this
                    // early in the lifecycle. Real attackers have the
                    // same constraint.
                    val diskLoader = ctor.newInstance(
                        tmpPayload.absolutePath, "/data/local/tmp", null, parent,
                    ) as ClassLoader
                    val diskCls = runCatching { diskLoader.loadClass("Payload") }.getOrNull()
                    XposedBridge.log(
                        "[$TAG] disk loader=$diskLoader resolved=${diskCls?.name}",
                    )
                } catch (t: Throwable) {
                    XposedBridge.log("[$TAG] disk DexClassLoader failed: $t")
                }
            }
        } catch (t: Throwable) {
            XposedBridge.log("[$TAG] injection failed: $t")
            Log.e(TAG, "injection failed", t)
            return
        }

        // ---- Schedule a verify pass long after the prewarm has run ------
        // This proves the detector now has a chance to see (or miss)
        // the injection in steady state. The verify is on a background
        // thread so we don't block the host's main thread.
        Thread({ verifyAfterDelay(lpparam) }, "$TAG-verify").start()
    }

    private fun verifyAfterDelay(lpparam: XC_LoadPackage.LoadPackageParam) {
        // 4 s — comfortable margin past the prewarm landing on a Pixel
        // 6 Pro. The exact value isn't load-bearing; we just need to be
        // past the first-evaluate snapshot.
        Thread.sleep(VERIFY_DELAY_MS)

        val ctx = currentApplicationContext()
        if (ctx == null) {
            XposedBridge.log("[$TAG] no Application at verify time — bailing")
            return
        }
        val di = resolveDeviceIntelligenceInstance(lpparam)
        if (di == null) {
            XposedBridge.log("[$TAG] no DeviceIntelligence singleton at verify time — wrong build?")
            return
        }

        val kinds = collectRuntimeDexKinds(di, ctx)
        if (kinds.isEmpty()) {
            XposedBridge.log(
                "[$TAG] FLAG NOT CAPTURED — runtime.environment dex-injection " +
                    "channel returned 0 findings post-injection. This confirms the " +
                    "pre-baseline timing gap: channel (a) saw the foreign DEX as " +
                    "part of the snapshot, channel (b) either raced or also " +
                    "snapshotted post-injection. Detector needs an " +
                    "`unattributable_dex_at_baseline` signal.",
            )
            Log.w(TAG, "FLAG NOT CAPTURED — pre-baseline timing gap confirmed")
        } else {
            XposedBridge.log(
                "[$TAG] FLAG CAPTURED — pre-baseline injection still surfaced as: $kinds. " +
                    "Most likely channel (b) snapshotted before ART minted the anon region.",
            )
            Log.w(TAG, "FLAG CAPTURED — kinds=$kinds")
        }
    }

    private fun resolveDeviceIntelligenceInstance(lpparam: XC_LoadPackage.LoadPackageParam): Any? =
        runCatching {
            val cls = XposedHelpers.findClass(DI_CLASS, lpparam.classLoader)
            XposedHelpers.getStaticObjectField(cls, "INSTANCE")
        }.getOrNull()

    private fun currentApplicationContext(): Context? = runCatching {
        val cls = Class.forName("android.app.ActivityThread")
        val method = cls.getDeclaredMethod("currentApplication").apply { isAccessible = true }
        (method.invoke(null) as? Application)?.applicationContext
    }.getOrNull()

    private fun collectRuntimeDexKinds(diInstance: Any, ctx: Context): List<String> {
        val report = runCatching {
            XposedHelpers.callMethod(diInstance, "collectBlocking", ctx)
        }.getOrNull() ?: return emptyList()
        val detectors = runCatching {
            XposedHelpers.callMethod(report, "getDetectors") as? List<*>
        }.getOrNull().orEmpty()
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
                val kind = runCatching {
                    XposedHelpers.callMethod(f, "getKind") as? String
                }.getOrNull() ?: continue
                if (kind !in DEX_INJECTION_KINDS) continue
                val message = runCatching {
                    XposedHelpers.callMethod(f, "getMessage") as? String
                }.getOrNull().orEmpty()
                XposedBridge.log("[$TAG verify]   finding kind=$kind message=\"$message\"")
                kinds += kind
            }
            return kinds
        }
        return emptyList()
    }

    private companion object {
        const val TAG = "DI-LSPEarlyHook"
        const val TARGET_PACKAGE = "io.ssemaj.sample"
        const val DI_CLASS = "io.ssemaj.deviceintelligence.DeviceIntelligence"
        const val VERIFY_DELAY_MS = 4_000L

        /** Same set as [DexInjectionHook.DEX_INJECTION_KINDS] — duplicated to avoid cross-file wiring. */
        val DEX_INJECTION_KINDS = setOf(
            "dex_classloader_added",
            "dex_path_outside_apk",
            "dex_in_memory_loader_injected",
            "dex_in_anonymous_mapping",
            "unattributable_dex_at_baseline",
        )
    }
}
