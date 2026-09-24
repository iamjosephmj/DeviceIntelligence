package tech.thessemaj.deviceintelligence.sample.data

import android.app.Application
import android.os.SystemClock
import android.util.Log
import tech.thessemaj.deviceintelligence.api.DeviceIntelligence
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.domain.ScanRepository
import tech.thessemaj.deviceintelligence.sample.domain.model.Timed
import tech.thessemaj.deviceintelligence.verifier.ScanResult
import tech.thessemaj.deviceintelligence.verifier.ScanSession
import tech.thessemaj.deviceintelligence.verifier.ScanVerifier
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The only place that touches the SDK or the in-app verifier.
 *
 * This is also the only place that logs. One tag for the whole sample —
 * `adb logcat -s DiSample` — and the lines are a contract: `tools/qa/fp-harness.sh`
 * and the device sweep parse them, so their shape must not change casually.
 */
@Singleton
class IntelScanRepository @Inject constructor(
    private val application: Application,
    private val io: CoroutineDispatcher,
) : ScanRepository {

    private val verifier by lazy { ScanVerifier() }

    /**
     * The backend half of the dev licence key. TEST-ONLY and deliberately shipped
     * here so the demo closes on-device; a real deployment keeps this on the server
     * and mints it with the `deviceintelligenceGenerateKey` Gradle task.
     *
     * The verifier loads the key itself from the raw resource — the app never touches
     * KeyFactory. That matters below API 33, where Conscrypt has no XDH provider and
     * building the key in the app threw NoSuchAlgorithmException before the library's
     * fallback could ever run.
     */
    private val serverKey by lazy {
        verifier.serverKeyFrom(application.resources.openRawResource(R.raw.dev_backend_priv))
    }

    override suspend fun warmUp() {
        // DeviceIntelligence.initialize registers the shim on its first call, so the Initialize
        // button re-entering here is a no-op.
        withContext(io) { DeviceIntelligence.initialize(application) }
    }

    override suspend fun initialize(): Timed<Boolean> = withContext(io) {
        // initialize() registers the framework shim and hands over the app context on
        // its first call, so there is no separate bootstrap step.
        val t0 = SystemClock.elapsedRealtime()
        val licensed = DeviceIntelligence.initialize(application)
        val ms = SystemClock.elapsedRealtime() - t0
        Log.i(TAG, "initialize licensed=$licensed in ${ms}ms")
        Timed(licensed, ms)
    }

    override suspend fun startSession(sessionId: String): Timed<Boolean> = withContext(io) {
        val t0 = SystemClock.elapsedRealtime()
        val prepared = DeviceIntelligence.setSession(sessionId)
        val ms = SystemClock.elapsedRealtime() - t0
        Log.i(TAG, "setSession attested=${sessionId.isNotEmpty()} in ${ms}ms")
        runCatching { application.filesDir.resolve("session-id.txt").writeText(sessionId) }
        Timed(prepared, ms)
    }

    override suspend fun scan(reason: String): Timed<String> = withContext(io) {
        val t0 = SystemClock.elapsedRealtime()
        val token = DeviceIntelligence.scan(reason)
        val ms = SystemClock.elapsedRealtime() - t0
        runCatching { application.filesDir.resolve("scan.token").writeText(token) }
        Timed(token, ms)
    }

    override suspend fun verify(
        token: String,
        sessionId: String,
        bound: ScanSession?,
    ): Result<ScanResult> = withContext(io) {
        // The old `.getOrNull()` discarded the exception, which is why the Android 9 XDH
        // failure showed as a bare "VERIFY ERROR" with nothing in logcat, twice.
        runCatching { verifier.verifyScan(token, sessionId, serverKey, bound) }
            .onFailure { Log.e(TAG, "verifyScan threw", it) }
            .onSuccess { r ->
                // The verdict, its reason and any failed gate — enough to tell from a
                // logcat alone WHY a device was rejected, without a screenshot.
                Log.i(
                    TAG,
                    "scan ok=${r.ok} deviceIntegrityOk=${r.deviceIntegrityOk} reason=${r.reason} " +
                        "bootstrap=${r.bootstrap} signals=${r.signals.size}",
                )
                r.checks.filter { !it.ok }.forEach {
                    Log.w(
                        TAG,
                        "scan check FAILED: ${it.name}" +
                            if (it.detail.isEmpty()) "" else " — ${it.detail}",
                    )
                }
            }
    }

    override fun newSessionId(): String =
        ByteArray(32).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }

    private companion object {
        /** One logcat tag for the whole sample: `adb logcat -s DiSample`. */
        const val TAG = "DiSample"
    }
}
