package tech.thessemaj.deviceintelligence.dx

/**
 * device-intelligence-lab — the JVM entry point to the native device-integrity engine.
 *
 * WHAT THIS IS
 * ------------
 * A **detection-only** device-integrity library. The prebuilt native core
 * (`libdicore.so`) runs a suite of on-device tamper/integrity detectors and
 * returns a **verdict**. There is **no on-device enforcement** — nothing crashes
 * the host. The decision is meant to be made server-side: the app validates its
 * licence once ([initialize]), hands the SDK its session id ([setSession]), then
 * calls [scan] per request; each returns an encrypted token the app forwards to a
 * backend, which decrypts it and decides.
 *
 * (This is a fork of an active RASP whose enforcement subsystem — an out-of-process
 * ptrace/watchdog kill — has been deleted. The obfuscated build pipeline and the
 * detectors are retained; only the "kill" is gone.)
 *
 * THE THREE CALLS (no SDK-owned network endpoint)
 * -----------------------------------------------
 * ```
 * NativeBridge.initialize()                    // local: licence validation, no network
 * NativeBridge.setSession(sessionId)           // your own backend's session id
 * val token = NativeBridge.scan("checkout")    // detectors + TEE -> one encrypted string
 * ```
 * There is nothing to fetch before [initialize] and no enrollment endpoint. The
 * FIRST [scan] of a cold start attests a hardware key bound to the session id and
 * carries the certificate chain; later scans sign with that key and are cheap. The
 * session id is therefore the server-issued value everything binds to — see
 * [setSession] for what it must satisfy. Minimum API 28.
 *
 * WHAT THE DETECTORS COVER
 * ------------------------
 * TEE key-attestation (chain to pinned Google roots, offline revoked-keybox CRL,
 * cross-level StrongBox/TEE keybox reuse, device-property honeypot) · APK
 * self-integrity (v2/v3 signing-block + entry diff) · ART/JNI integrity (method
 * entry-point, JNIEnv table, inline prologue, ACC_NATIVE flip) · native
 * self-integrity (.text hash, GOT/PLT, libc .text + load-backing, prologue
 * trampolines, caller/return-address, injected libs/anon-exec) · environment
 * (ptrace/TracerPid, Frida ports/threads/maps, RWX, seccomp-kill-filter) · root
 * (su, Magisk, KernelSU, TLS trust-store swap) · emulator (arm64 CNTFRQ, x86 CPUID
 * hypervisor) · app-cloner (foreign APK maps, mount namespace, UID mismatch).
 * Every detector fails **open**: an input it cannot read contributes nothing.
 *
 * TOKEN FORMAT (returned by [scan])
 * ---------------------------------
 * The device is a SIGNED SENSOR: it reports raw signals; the BACKEND decides
 * clean/compromised. There is NO on-device verdict (no critical/clean). The token
 * is the hex of a keystream-XOR ciphertext; decrypted it is:
 * ```
 * <signed_content JSON>
 * --BINDING
 * SIG  FS <hex ECDSA signature over signed_content>
 * CERT FS <hex DER cert>   // hardware attestation chain, leaf first
 * ```
 * `signed_content` is compact single-line JSON:
 * ```
 * {"schemaVersion":4,"type":"scan","sessionId":"…","name":"checkout",
 *  "ts":<epoch>,"bootstrap":true,"attestedKey":"<hex spki>",
 *  "app":{"package":"…","signer":"<sha256 hex>"},
 *  "device":{"api":36,"abi":"arm64-v8a","model":"…"},
 *  "signals":[{"id":"INTEL_0018","severity":"CRITICAL","detail":"enforce=0"}, …]}
 * ```
 * Each signal is an OPAQUE code — `detector`/`kind` never leave the device. The
 * code↔meaning map is tools/registry/signals-registry.json (append-only), resolved by the
 * backend. `severity` is a device HINT; the server reweights it. Full contract +
 * backend decision: tools/server/SCHEMA.md.
 *
 * TOKEN CRYPTO (v2 ECIES — the default build)
 * -------------------------------------------
 * ```
 *   token  = "2:" + hex(version(1)||epoch(1)||eph_pub(32)||nonce(12)||ct||tag(16))
 *   shared = X25519(server_priv, eph_pub)
 *   key    = HKDF-SHA256(ikm=shared, salt=nonce, info="intel-token-v2"||epoch, 32)
 *   plain  = AES-256-GCM-open(key, nonce, ct||tag, aad=version||epoch||eph_pub)
 * ```
 * The device holds only the server PUBLIC key (in the licence blob), so there
 * is no extractable transport secret to lift out of the APK — the v1 symmetric
 * keystream it replaced could be forged by anyone who recovered the baked key.
 * Unforgeability rests on the INNER hardware signature; v2 secures the outer
 * envelope only. The backend refuses a v1 token outright rather than accept one on
 * the strength of a baked constant, so a v1 build cannot bootstrap a session.
 *
 * (`-Pdeviceintelligence.tokenV2=0` still builds the v1 keystream envelope. It exists only for
 * bisecting the native envelope against an old backend and produces tokens the scan
 * path rejects.)
 *
 * JNI SURFACE (opaque names, bound via RegisterNatives — only `JNI_OnLoad` is exported)
 * ------------------------------------------------------------------------------------
 *  - [e]  native impl behind [initialize]: validate the licence blob -> "1" or "".
 *         Takes a reserved String the ABI still declares but the call ignores.
 *  - [p]  native impl behind [setSession]: attest ONCE for this session and cache
 *         the chain in process memory. The only expensive call in the SDK.
 *  - [c]  native impl behind [scan]: run detectors -> sign with the session key ->
 *         encrypt. No attestation and no keygen — it reads the cache [p] populated
 *         — but it does one TEE-resident ECDSA sign with the attested key.
 *  - [r]  liveness (native core loaded and bound).
 *  - [s]  register the framework-shim `Class` so native up-calls (TEE keygen, apk /
 *         cloner JVM inputs) resolve without a literal class name. Call once at
 *         bootstrap; attestation / apk / cloner detectors need it to produce findings.
  *  - [g]  no longer backs a feature. It is retained deliberately: `jni_register`
  *         binds it BY NAME, so deleting the declaration fails RegisterNatives and
  *         takes JNI_OnLoad down with it, and `prologue_verify` uses its address as
  *         one of four anchors for the native inline-hook check (INTEL_0003).
 */
object NativeBridge {

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var loadError: Throwable? = null

    init {
        try {
            System.loadLibrary("dicore")
            loaded = true
        } catch (t: Throwable) {
            loadError = t
        }
    }

    /** True if libdicore.so loaded and the SHA backend is bound. */
    fun isReady(): Boolean = loaded && runCatching { r() }.getOrDefault(false)

    /** Throwable from the [System.loadLibrary] attempt, if any. */
    fun loadError(): Throwable? = loadError

    @Volatile
    private var sessionId: String = ""

    /**
     * Validate the licence blob and prepare the native core. Local: no network, no
     * TEE, no keystore, nothing to fetch first.
     *
     * Returns false when the blob is missing, unsigned, bound to a different package,
     * or expired — but false is NOT a reason to stop. A blob that PARSED still carries
     * a usable server public key, so [scan] emits a DEGRADED token naming the
     * rejection (`INTEL_0054`) rather than nothing. Only a blob that did not parse at
     * all leaves [scan] returning "", because the key it would encrypt to lives
     * inside that blob.
     *
     * This is a FAIL-FAST, not a security control: an attacker who has patched the
     * native core has patched this check with it. The enforcing licence check is
     * backend-side, on the app identity the TEE attested.
     *
     * Safe to call before [s]: the licence blob and the package name are read
     * through the framework shim, and an evaluation made before that shim is
     * registered has nothing to judge, so it returns false WITHOUT caching the
     * answer. Bootstrap order still matters for the detectors, but a too-early
     * [initialize] no longer latches the process into a permanent "unlicensed".
     */
    fun initialize(): Boolean =
        if (loaded) runCatching { e("") }.getOrNull() == "1" else false

    /**
     * Store the app's server-issued session id. MUST be called before [scan].
     *
     * The id MUST be opaque, unpredictable, at least 128 bits of entropy, issued per
     * session by your backend, and never derived from a stable identifier (user id,
     * device id, account email). It is the value the hardware attestation binds to,
     * so a guessable or shared id silently removes replay protection — there is no
     * error and no signal, because the SDK cannot detect it. If your session id
     * cannot meet this, use [scan] with an explicit per-request nonce instead.
     *
     * BLOCKING AND SLOW: this is where the hardware attestation happens — one TEE or
     * StrongBox keygen, typically ~150ms and up to a couple of seconds on devices
     * backing StrongBox with a slow secure element. It is done here, once, so that
     * [scan] never attests again. Call it off the UI thread.
     *
     * (Each [scan] still performs one ECDSA signature with the attested key, which
     * happens inside the TEE — a few milliseconds. What moved off the request path
     * is the ATTESTATION, not TEE use altogether.)
     *
     * Returns false if the attestation could not be produced, in which case [scan]
     * will return "". Re-setting the SAME id is a no-op; a different id re-attests,
     * because a chain bound to the old session is of no use to the backend.
     */
    fun setSession(id: String): Boolean {
        sessionId = id
        return loaded && id.isNotEmpty() && runCatching { p(id) }.getOrDefault(false)
    }

    /**
     * Run a scan for the given call-site (e.g. "login", "checkout"). Returns the
     * encrypted token to forward to your backend.
     *
     * The FIRST scan after a cold start is the expensive one: it carries the
     * certificate chain [setSession] attested. Every later scan signs with that key
     * and is cheap. Do the first one off the UI thread.
     *
     * FAILS LOUD, NOT OPEN. A scan whose licence, session or attestation is missing
     * still returns a token — a DEGRADED one, which names its own missing binding
     * and carries the detector findings anyway. This call therefore does NOT check
     * whether [initialize] or [setSession] succeeded: those gates are the first
     * thing a hook engine breaks, and returning "" for them made SUPPRESSING the SDK
     * cheaper than defeating it, because silence at your backend is
     * indistinguishable from a network error or an app that never integrated.
     *
     * A degraded token is unauthenticated and your backend will reject it as such —
     * it is never evidence of a clean device. It is evidence that something stopped
     * this device from binding itself, which is worth strictly more than nothing.
     *
     * Returns "" only when the native core did not load, or when the licence blob
     * could not be parsed at all: the server public key lives inside that blob, so
     * there is then nothing to encrypt a token to.
     */
    fun scan(name: String): String =
        if (loaded) runCatching { c(sessionId, name, "") }.getOrDefault("") else ""

    /**
     * As [scan], with an explicit server-issued per-request nonce — for apps whose
     * session id cannot meet the entropy requirement documented on [setSession].
     */
    fun scan(name: String, nonce: String): String =
        if (loaded) runCatching { c(sessionId, name, nonce) }.getOrDefault("") else ""

    /**
     * Legacy [initialize] that accepted an enrollment challenge.
     *
     * The argument is **ignored**. Enrollment no longer exists as a separate step: the
     * hardware attestation moved to [setSession], because an attestation challenge has to
     * sit inside a certificate the device mints, so it can only bind to a value that
     * already exists — and at `initialize()` time there is no session yet.
     *
     * @param enrollChallenge ignored, retained only so existing call sites still compile.
     * @return `"1"` if the licence validated, `""` otherwise — the old string-valued
     *   convention. Prefer the boolean [initialize].
     */
    @Deprecated(
        "The backend no longer issues an enrollment challenge; the argument is ignored.",
        ReplaceWith("initialize()"),
    )
    fun initialize(enrollChallenge: String): String = if (initialize()) "1" else ""

    /**
     * Former name of [scan]. Behaviour is unchanged — this call always was a scan, and
     * the `challenge` argument is the per-request nonce that [scan] takes as `nonce`.
     *
     * @param name the scan point, e.g. `"checkout"`.
     * @param challenge a fresh per-request server nonce.
     * @return the encrypted token, or `""` — see [scan].
     */
    @Deprecated(
        "Renamed: this call is a scan.",
        ReplaceWith("scan(name, challenge)"),
    )
    fun challenge(name: String, challenge: String): String = scan(name, challenge)

    // ---- Native entry points -------------------------------------------------------
    // Deliberately single-letter: these are the symbols an attacker greps for first, and
    // they cross the JNI boundary where the Kotlin-side names are the ones that survive
    // into the DEX. Call the documented wrappers above instead — these take no
    // precautions about state and will return "" if the session was never prepared.

    /** True once the native core has completed its first clean sweep. */
    @JvmStatic
    external fun r(): Boolean

    /** Native impl behind [initialize]: validate the licence blob. Returns `"1"` or `""`. */
    @JvmStatic external fun e(enrollChallenge: String): String

    /** Native impl behind [setSession]: attest once for this session and cache it. */
    @JvmStatic external fun p(sessionId: String): Boolean

    /**
     * Native impl behind [scan]: sweep, sign with the cached attested key, encrypt.
     * Returns `""` unless [p] has succeeded for this same `sessionId`.
     */
    @JvmStatic external fun c(sessionId: String, name: String, challenge: String): String

    /** Sweep-gated consumer-string key. Blocks until the first clean sweep. */
    @JvmStatic
    external fun g(seedHex: String): String

    /** Register the framework-shim class with native (call once at bootstrap). */
    @JvmStatic
    external fun s(shim: Class<*>)
}
