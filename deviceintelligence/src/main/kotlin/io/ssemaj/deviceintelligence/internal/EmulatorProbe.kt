package io.ssemaj.deviceintelligence.internal

import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity

/**
 * `runtime.emulator` — CPU-instruction emulator detector.
 *
 * Drives the per-ABI native probe (`emu_probe_arm64.cpp` /
 * `emu_probe_x86_64.cpp`) and emits a single
 * `kind="running_on_emulator"` [Finding] when the native side
 * flagged a decisive signal.
 *
 * The probe reads architectural CPU state (system registers on
 * arm64, CPUID leaves on x86_64) — these can't change for the
 * lifetime of a process, so the result is cached.
 *
 * Stays declared as `object` (not `class`) because the JNI symbol
 * binding for `nativeEmulator*` is keyed on the outer class name
 * (`Java_io_ssemaj_deviceintelligence_internal_EmulatorProbe_*`); moving the
 * methods into a companion would change that to
 * `Java_..._EmulatorProbe_00024Companion_*` and silently break the
 * lookup at runtime.
 */
internal object EmulatorProbe : Detector {

    private const val TAG = "DeviceIntelligence.EmulatorProbe"

    override val id: String = "runtime.emulator"

    @Volatile
    private var cached: List<Finding>? = null
    private val lock = Any()

    @JvmStatic private external fun nativeEmulatorDecisive(): Boolean
    @JvmStatic private external fun nativeEmulatorRawSignals(): String

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        if (!ctx.nativeReady) {
            return inconclusive(
                id, "native_not_ready",
                "dicore native lib not loaded", dur(),
            )
        }

        val findings = synchronized(lock) {
            cached ?: doEvaluate().also { cached = it }
        }
        return ok(id, findings, dur())
    }

    private fun doEvaluate(): List<Finding> = try {
        val decisive = nativeEmulatorDecisive()
        val raw = nativeEmulatorRawSignals()
        Log.i(TAG, "probe: decisive=$decisive raw=$raw")
        if (!decisive) {
            emptyList()
        } else {
            listOf(
                Finding(
                    kind = "running_on_emulator",
                    severity = Severity.HIGH,
                    subject = null,
                    message = "CPU-instruction probe indicates the process is running inside a hypervisor / QEMU",
                    details = parseRawSignals(raw),
                ),
            )
        }
    } catch (t: Throwable) {
        // Probe is best-effort. Don't escalate a runtime crash into
        // an ERROR detector — log and treat as "no signal".
        Log.w(TAG, "emulator probe threw, treating as no-signal", t)
        emptyList()
    }

    /**
     * The native side packs its raw signals as `key=value|key=value`
     * for compactness. Unpack into a real map for the [Finding] details.
     */
    private fun parseRawSignals(raw: String): Map<String, String> {
        if (raw.isEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (kv in raw.split('|')) {
            val eqIdx = kv.indexOf('=')
            if (eqIdx <= 0) continue
            out[kv.substring(0, eqIdx)] = kv.substring(eqIdx + 1)
        }
        return out
    }

    /** Test-only: drop the cached verdict so the next [evaluate] re-runs the native probe. */
    fun resetForTest() {
        synchronized(lock) { cached = null }
    }
}
