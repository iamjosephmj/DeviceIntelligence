package io.ssemaj.deviceintelligence.internal

import android.annotation.TargetApi
import android.app.AppComponentFactory
import android.app.Application
import android.util.Log

/**
 * Earliest-possible bootstrap hook for DeviceIntelligence.
 *
 * Android's [AppComponentFactory] is the first user-customisable
 * extension point in the app's lifecycle. The framework calls
 * [instantiateApplication] BEFORE the [Application] instance even
 * exists — which means before:
 *
 *  - `Application.attachBaseContext(...)`
 *  - any `ContentProvider.attachInfo(...)` (including ours and
 *    every AndroidX `Initializer` registered via Startup)
 *  - `Application.onCreate(...)`
 *  - any `Activity` / `Service` / `BroadcastReceiver` lifecycle
 *
 * Inside the override we touch [NativeBridge.isReady] purely as a
 * side effect of the JVM's class-init contract: that triggers
 * `System.loadLibrary("dicore")`, which in turn fires
 * `JNI_OnLoad` and captures the G3/G7 baseline against the
 * earliest possible snapshot of the process. Running here closes
 * a race that the [DeviceIntelligenceInitProvider] alone cannot:
 * a higher-priority library running in `Application.attachBaseContext`
 * (or in its own pre-baseline ContentProvider) would otherwise
 * have a window to dlopen something between zygote-fork and our
 * baseline capture.
 *
 * Wiring (see `AndroidManifest.xml`): we declare this class as
 * `<application android:appComponentFactory="...">` in our
 * library manifest WITHOUT `tools:replace`. AGP's standard
 * manifest-merger precedence rules then mean:
 *
 *   - Consumer that defines no `appComponentFactory` → ours is
 *     merged in and used. Earliest bootstrap engaged.
 *   - Consumer that defines its own `appComponentFactory` → its
 *     value wins, ours is silently dropped, no merge conflict
 *     raised, no consumer breakage. The `DeviceIntelligenceInitProvider`
 *     fallback still runs at `initOrder = MAX_VALUE`.
 *
 * Either way, the consumer never has to think about us; the
 * worst case (consumer-defined factory) just falls back to the
 * already-effective ContentProvider bootstrap.
 *
 * API level: [AppComponentFactory] was added in API 28. On
 * older devices the manifest attribute is silently ignored and
 * this class is never loaded by the framework; the
 * ContentProvider-based path remains the bootstrap. We use
 * `@TargetApi(28)` to tell lint we know what we're doing rather
 * than `@RequiresApi`, because no other code in this module
 * references `DeviceIntelligenceComponentFactory` — the only
 * load site is the framework's manifest-driven instantiation,
 * which already gates on API level.
 *
 * Why we DON'T do the prewarm `collect()` here too: prewarm needs
 * a `Context`, which doesn't exist yet when [instantiateApplication]
 * runs (it's literally what's being instantiated). The bootstrap
 * split — native lib + JNI_OnLoad here, prewarm collect in the
 * ContentProvider once Context is available — is intentional.
 *
 * Why the catch-all in [instantiateApplication]: this is called
 * by the framework with reflection-style guarantees; throwing
 * here would crash every consumer app dead before any logging
 * could surface. The native lib load failing is recoverable
 * (consumer's first `collect()` will return an inconclusive
 * result with `nativeReady=false`); a crash in the framework's
 * `instantiateApplication` callback is not.
 */
@TargetApi(28)
internal class DeviceIntelligenceComponentFactory : AppComponentFactory() {

    override fun instantiateApplication(cl: ClassLoader, className: String): Application {
        try {
            // Touching NativeBridge triggers its `init {}` /
            // companion-object loadLibrary; that fires JNI_OnLoad
            // which runs `dicore::native_integrity::initialize`,
            // which in turn captures the G3/G7 baseline against
            // the earliest possible snapshot of the process.
            NativeBridge.isReady()
            Log.i(LOG_TAG, "AppComponentFactory bootstrap: native lib loaded before Application instance")
        } catch (t: Throwable) {
            Log.w(LOG_TAG, "earliest-bootstrap native load threw; falling back to provider", t)
        }
        return super.instantiateApplication(cl, className)
    }

    private companion object {
        const val LOG_TAG: String = "DeviceIntelligence"
    }
}
