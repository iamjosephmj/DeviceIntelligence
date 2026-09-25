package tech.thessemaj.deviceintelligence.api

import android.app.Application
import tech.thessemaj.deviceintelligence.dx.NativeBridge
import tech.thessemaj.deviceintelligence.internal.FrameworkShim
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Coroutine-friendly facade over [NativeBridge].
 *
 * [NativeBridge] is the raw JNI surface: single-letter natives, `""`/`"1"` sentinels, and two
 * calls that block long enough to matter on the main thread. This wraps it in the
 * three-step flow the SDK actually has — [initialize] once, [setSession] per
 * session, [scan] per request — and moves the blocking off the caller's thread.
 *
 * ```
 * DeviceIntelligence.initialize(application)          // licence, local
 * DeviceIntelligence.setSession(idFromYourBackend)    // attests ONCE
 * val token = DeviceIntelligence.scan("checkout")     // forward to your backend
 * ```
 *
 * All three run on [Dispatchers.IO] under one [mutex], so the native core sees a
 * strictly serial call sequence no matter how many coroutines race here. That
 * matters because the steps are ordered: a [scan] overlapping the [setSession] it
 * depends on would read a half-installed session.
 */
object DeviceIntelligence {

    private val mutex = Mutex()

    // Guarded by [mutex]: every read and write happens inside withLock, which
    // supplies the happens-before. No @Volatile needed on top of that.
    private var shimRegistered = false

    /**
     * Register the framework shim, hand the core an application context, and
     * validate the licence blob. Local: no network, no TEE, no keystore.
     *
     * Safe to call more than once — the shim is registered on the first call only,
     * and the licence is re-evaluated cheaply after that.
     *
     * @return true when the licence blob validated.
     *
     *   False does NOT mean stop. Which failure it was decides what [scan] can still
     *   do, and the distinction is load-bearing:
     *
     *   - **Parsed but rejected** (expired, or bound to another package) — the blob
     *     still carries a usable server public key, so [scan] emits a DEGRADED token
     *     that NAMES the rejection (`INTEL_0038`) and carries the detector findings.
     *     Send it. Silence is what an attacker wants: at the backend, no token is
     *     indistinguishable from a network error or an app with no SDK at all.
     *   - **Unparseable or missing** from `assets/tech.thessemaj.deviceintelligence/server.key` — there
     *     is no key to encrypt to, so [scan] returns `""`. This is the one
     *     unavoidable silence.
     *
     *   See `token_encode` in orchestrate.cpp, which gates on PARSED, not on ok.
     */
    suspend fun initialize(application: Application): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (!shimRegistered) {
                // Order matters: native resolves the shim class first, then reads
                // the licence asset and package name through it.
                //
                // Guarded because NativeBridge.s is a raw external fun with no internal catch:
                // if libdicore.so never loaded it throws UnsatisfiedLinkError.
                // A core that is not there is exactly the case initialize() must
                // report as `false`, not crash the host on.
                runCatching { NativeBridge.s(FrameworkShim::class.java) }
                runCatching { FrameworkShim.setContext(application) }
                shimRegistered = true
            }
            NativeBridge.initialize()
        }
    }

    /**
     * Store the session id everything binds to, and attest a hardware key against it.
     *
     * The id MUST come from your backend and be opaque, unpredictable and per-session
     * — it is the attestation challenge, so a guessable or reused value silently
     * removes replay protection. See [NativeBridge.setSession].
     *
     * Blocking and slow by design: this is the one TEE/StrongBox keygen, which is why
     * it is here and not on the scan path.
     *
     * @return true when the attestation was produced. False still leaves [scan]
     *   usable — it emits a DEGRADED token naming the missing binding.
     */
    suspend fun setSession(sessionId: String): Boolean = withContext(Dispatchers.IO) {
        mutex.withLock { NativeBridge.setSession(sessionId) }
    }

    /**
     * Run a scan for the given call-site and return the encrypted token to forward
     * to your backend.
     *
     * The first scan after [setSession] is the expensive one — it carries the
     * certificate chain. Later scans sign with the attested key and are cheap.
     *
     * @param scenarioName the scan point, e.g. `"checkout"`.
     * @param nonce optional fresh per-request server nonce.
     * @return the token, or `""` when the licence blob did not parse — the one case
     *   with nothing to encrypt to. Every other failure still returns a token.
     */
    suspend fun scan(scenarioName: String, nonce: String = ""): String = withContext(Dispatchers.IO) {
        mutex.withLock { NativeBridge.scan(scenarioName, nonce) }
    }

    /** True once the native core is loaded and bound. Diagnostics only. */
    fun isReady(): Boolean = NativeBridge.isReady()

    /** The [System.loadLibrary] failure, if the core never loaded. Diagnostics only. */
    fun loadError(): Throwable? = NativeBridge.loadError()
}
