package tech.thessemaj.deviceintelligence.sample.data

import android.app.Application
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.util.Log
import tech.thessemaj.deviceintelligence.api.DeviceIntelligence
import tech.thessemaj.deviceintelligence.dx.NativeBridge
import tech.thessemaj.deviceintelligence.sample.BuildConfig
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.verifier.ScanSession
import tech.thessemaj.deviceintelligence.verifier.ScanVerifier
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * DEBUG-ONLY red-team hook. Never referenced from a release build: the only
 * caller ([tech.thessemaj.deviceintelligence.sample.ui.scan.ScanViewModel.onChaos]) sits behind a
 * `BuildConfig.DEBUG` guard that the compiler folds away in release.
 *
 * One press runs the three on-device attacks the anti-capture campaign must
 * prove are detected (see corpus/red-team and docs/signals.md):
 *
 *  a. `mmap`s one anonymous `PROT_EXEC|PROT_READ|PROT_WRITE` page and never
 *     unmaps it — the zygisk-style injection footprint `INTEL_0057` flags.
 *     Nothing is written to it and nothing jumps into it: the mapping itself
 *     is the attack.
 *  b. Drives `DeviceIntelligence.scan("chaos")` in a tight loop of 50 — the scripted sweep
 *     `INTEL_0058`'s rate guard exists for, through the public facade (whose
 *     mutex serializes the channel, as an honest integration sees it).
 *  c. Drives the RAW channel — `NativeBridge.scan` directly, no facade mutex — from 32
 *     concurrent threads. That is how an actual capture harness sweeps: when
 *     one scan costs seconds (this lab device's detector load), only a
 *     parallel raw drive can put 30 scan entries inside the 10 s window and
 *     trip `rate_exhausted=1`.
 *
 * Every produced token is kept under `files/chaos/<n>.token` (sequential) and
 * `files/chaos-c/t<thread>-<round>.token` (concurrent) so the exact scan that
 * trips the guard can be identified afterwards by decoding them with the
 * backend verifier (the sample's own half or the `:verifier` CLI). The last
 * token of each phase is also verified in-process and its signal ids logged,
 * so the run is legible from `adb logcat -s DiSample` alone.
 */
@Singleton
class ChaosHook @Inject constructor(
    private val application: Application,
    private val io: CoroutineDispatcher,
) {

    private val verifier by lazy { ScanVerifier() }

    /** Same TEST-ONLY dev backend key the repository's in-app verify half uses. */
    private val serverKey by lazy {
        verifier.serverKeyFrom(application.resources.openRawResource(R.raw.dev_backend_priv))
    }

    /** Address of the leaked RWX page, 0 until [run] maps it. Exposed for logs/UI. */
    @Volatile
    var rwxPage: Long = 0
        private set

    /** How many synthetic scans one press drives — matches the red-team brief. */
    val sweepCount: Int = SWEEP

    /**
     * Map the RWX page, run both sweeps, persist every token, verify the last
     * token of each phase in-process. Returns a `seq:<ids> conc:<ids>` summary
     * of what the backend half saw.
     */
    suspend fun run(sessionId: String, bound: ScanSession?): String = withContext(io) {
        check(BuildConfig.DEBUG) { "chaos hook is debug-only" }

        // (a) Anonymous RWX page. address 0 lets the kernel choose; MAP_ANONYMOUS
        // takes no fd (null → -1). The address is kept so the mapping is
        // deliberate and observable — there is no munmap.
        //
        // MAP_ANONYMOUS is spelled 0x20 because the OsConstants field is
        // API-30-tagged and this sample supports 28; the value is the eternal
        // Linux/bionic constant (same one OsConstants resolves to).
        rwxPage = Os.mmap(
            /* address = */ 0L,
            /* byteCount = */ PAGE_BYTES,
            /* prot = */ OsConstants.PROT_EXEC or OsConstants.PROT_READ or OsConstants.PROT_WRITE,
            /* flags = */ OsConstants.MAP_PRIVATE or 0x20,   // MAP_ANONYMOUS
            /* fd = */ null,
            /* offset = */ 0L,
        )
        Log.i(TAG, "chaos rwx page mapped at 0x${java.lang.Long.toHexString(rwxPage)}")

        // (b) The synthetic sweep. Timing per scan goes to logcat so the run is
        // auditable without pulling a single token.
        val dir = File(application.filesDir, "chaos").apply { mkdirs() }
        var lastToken = ""
        val t0 = SystemClock.elapsedRealtime()
        for (i in 1..SWEEP) {
            val s = SystemClock.elapsedRealtime()
            val token = DeviceIntelligence.scan("chaos")
            val ms = SystemClock.elapsedRealtime() - s
            lastToken = token
            File(dir, "%02d.token".format(i)).writeText(token)
            Log.i(TAG, "chaos scan i=$i ms=$ms bytes=${token.length / 2}")
        }
        val sweepMs = SystemClock.elapsedRealtime() - t0

        // The sample's own backend half reads the last token back, so the press
        // itself reports what the server would see — signal ids included.
        val ids = verifyLast(lastToken, sessionId, bound)
        Log.i(TAG, "chaos sweep done in ${sweepMs}ms; last token signals=${if (ids.isEmpty()) "(none)" else ids}")

        // (c) Concurrent RAW-channel drive. The sequential loop above drives the
        // public facade, whose mutex serializes scans; on hardware this loaded
        // (this lab device's detectors make one scan take seconds) a serialized
        // sweep can never put 30 scan entries inside the 10 s rate window. A real
        // scripted drive does not go through the coroutine facade at all — it
        // hammers the raw channel from many threads, exactly like this. This is
        // the leg INTEL_0058's rate guard exists for.
        val dirC = File(application.filesDir, "chaos-c").apply { mkdirs() }
        val entries = AtomicInteger()
        val failures = AtomicInteger()
        val lastConc = AtomicReference("")
        val finish = CountDownLatch(CONC_THREADS)
        val t1 = SystemClock.elapsedRealtime()
        repeat(CONC_THREADS) { t ->
            Thread {
                try {
                    repeat(CONC_ROUNDS) { r ->
                        val token = NativeBridge.scan("chaos-conc")
                        if (token.isEmpty()) {
                            failures.incrementAndGet()
                        } else {
                            File(dirC, "t%02d-%d.token".format(t, r)).writeText(token)
                            lastConc.set(token)
                        }
                        val n = entries.incrementAndGet()
                        if (n % 16 == 0) Log.i(TAG, "chaos-conc entries=$n")
                    }
                } catch (e: Throwable) {
                    failures.incrementAndGet()
                    Log.e(TAG, "chaos-conc thread threw", e)
                } finally {
                    finish.countDown()
                }
            }.start()
        }
        finish.await()
        val concMs = SystemClock.elapsedRealtime() - t1

        val concIds = verifyLast(lastConc.get(), sessionId, bound)
        Log.i(
            TAG,
            "chaos-conc done: entries=${entries.get()} failures=${failures.get()} in ${concMs}ms; " +
                "last token signals=${if (concIds.isEmpty()) "(none)" else concIds}",
        )
        "seq:${ids.ifEmpty { "(none)" }} conc:${concIds.ifEmpty { "(none)" }}"
    }

    /** Verify one token with the in-app backend half; "" when it cannot be read. */
    private fun verifyLast(token: String, sessionId: String, bound: ScanSession?): String {
        if (token.isEmpty()) return "(no token)"
        return runCatching {
            verifier.verifyScan(token, sessionId, serverKey, bound).signals.joinToString(",") { it.id }
        }.onFailure { Log.e(TAG, "chaos verifyScan threw", it) }
            .getOrDefault("(verify failed)")
    }

    private companion object {
        /** One logcat tag for the whole sample: `adb logcat -s DiSample`. */
        const val TAG = "DiSample"
        const val PAGE_BYTES = 4096L
        const val SWEEP = 50
        const val CONC_THREADS = 32
        const val CONC_ROUNDS = 3
    }
}
