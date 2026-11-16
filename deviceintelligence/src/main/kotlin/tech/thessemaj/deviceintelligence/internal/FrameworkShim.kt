package tech.thessemaj.deviceintelligence.internal

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.util.Base64
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Logic-free JVM up-call surface for the native orchestrator (spec 03 §1/§3).
 *
 * As the detection + verdict + kill move into `libdicore.so` and the JVM stops
 * orchestrating, native still needs the handful of values Android exposes ONLY
 * to Java (no NDK API): the package name, UID, the on-disk APK path, the
 * installer, the debugger flag, and the app's debuggable bit. Native calls these
 * via JNI (`framework_shim.cpp`).
 *
 * Each method makes exactly one framework call and returns a raw value — it
 * holds NO comparison, threshold, severity, or allow-list. All of those live in
 * native. The app [Context] is cached once by the init provider at process
 * start; failures degrade to an empty/false value (native treats those as
 * "unknown" and never escalates).
 */
object FrameworkShim {

    @Volatile
    private var appContext: Context? = null

    @JvmStatic
    fun setContext(ctx: Context) {
        appContext = ctx.applicationContext ?: ctx
    }

    /**
     * Single obfuscated up-call entry point. Native reaches every framework value
     * through this ONE method (selected by [op]) instead of by descriptive method
     * names — so R8 renames the class AND every real getter, leaving only this one
     * obscure name kept (native resolves it by string via GetStaticMethodID). The
     * op codes are the only fixed contract with `framework_shim.cpp`.
     */
    // op map (maintainer-only; the names below are intentionally opaque so the
    // up-call surface reveals nothing in source/debug/decompile — R8 also strips
    // them in release): a1 packageName, a2 uid, a3 sourceDir, a4 installerPackage,
    // a5 primaryAbi, a6 fingerprintAsset, a7 attestChain, a8 attested keygen,
    // a11 splitSourceDirs ('\n'-joined; App Bundle / bundle mode),
    // a12 deviceIdentity (Build.* '\n'-joined), a18 strongBoxFeature ("1"/"0"/""),
    // a19 signingCertDigest (SHA-256 hex of the first APK signer),
    // a21 fingerprintRaw (widevine id/level + ANDROID_ID) — op 18.
    @JvmStatic
    fun q(op: Int, arg: Any?): Any? = runCatching {
        when (op) {
            // ops 1 (package), 2 (uid), 5 (abi) moved into native (framework_shim.cpp)
            // — no ART-hookable surface for those inputs anymore.
            3 -> a3()
            4 -> a4()
            6 -> a6()
            7 -> a7(arg as? ByteArray ?: ByteArray(0))
            8 -> a9(arg as? ByteArray ?: ByteArray(0))
            9 -> a10()
            10 -> a11()
            11 -> a12()
            13 -> a15()
            14 -> a16(arg as? ByteArray ?: ByteArray(0))
            15 -> a17(arg as? ByteArray ?: ByteArray(0))
            16 -> a18()
            17 -> a19()
            18 -> a21()
            19 -> a23()
            20 -> a24(arg as? ByteArray ?: ByteArray(0))
            21 -> lastKeygenError
            else -> null
        }
    }.getOrNull()

    /**
     * SHA-256 (lowercase hex) of the first APK signing certificate; "" when
     * unavailable.
     *
     * This is a SELF-REPORT and is treated as one: it is app-visible, so a patched
     * core sets it to whatever it likes. Its only value is server-side, cross-checked
     * against the TEE-signed attestationApplicationId — the disagreement is the
     * finding, never this value on its own. Fails open, so an unreadable digest emits
     * nothing rather than a false accusation.
     */
    private fun a19(): String = runCatching {
        val ctx = appContext ?: return@runCatching ""
        val pm = ctx.packageManager
        val signers = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNATURES).signatures
        } ?: return@runCatching ""
        val first = signers.firstOrNull() ?: return@runCatching ""
        MessageDigest.getInstance("SHA-256").digest(first.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }.getOrDefault("")

    /**
     * The fingerprint inputs that genuinely need the JVM, '\n'-joined in a FIXED
     * order: widevineId, widevineLevel, androidId.
     *
     * Everything else in the fingerprint — kernel release, build fingerprint,
     * security patch — is read natively, because those feed INTEL_0019 and must not
     * travel through an ART-hookable surface. These three have no native path:
     * MediaDrm is binder, ANDROID_ID is a ContentResolver read.
     *
     * Every field fails open to "" — an unreadable value must stay absent rather
     * than become a constant every such device would share. Native hashes the two
     * identity fields before they reach the wire; the raw values never leave here.
     */
    private fun a21(): String {
        fun wv(prop: String): String = runCatching {
            // Widevine UUID: edef8ba9-79d6-4ace-a3c8-27dcd51d21ed
            val drm = android.media.MediaDrm(
                java.util.UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L))
            val v = runCatching {
                drm.getPropertyByteArray(prop).joinToString("") { "%02x".format(it) }
            }.getOrElse { runCatching { drm.getPropertyString(prop) }.getOrDefault("") }
            drm.close()
            v
        }.getOrDefault("")

        val androidId = runCatching {
            android.provider.Settings.Secure.getString(
                appContext?.contentResolver ?: return@runCatching "",
                android.provider.Settings.Secure.ANDROID_ID) ?: ""
        }.getOrDefault("")

        return listOf(wv("deviceUniqueId"), wv("securityLevel"), androidId).joinToString("\n")
    }

    /** Split APK paths for an App Bundle install ('\n'-joined). "" if none/unknown. */
    private fun a11(): String = runCatching {
        appContext?.applicationInfo?.splitSourceDirs?.joinToString("\n").orEmpty()
    }.getOrDefault("")

    /** This device's identity (Build.*) '\n'-joined, for the native device-property
     *  honeypot comparison. Acquisition only — native owns the compare. "" on failure. */
    private fun a12(): String = runCatching {
        // Device-property attestation is requested only on API >= 31 (see a8). On
        // older devices the tags are never present, so return "" -> native
        // fw_device_identity().ok == false -> kUnavailable (fail-open), never a
        // false "stripped" finding on a genuine API 28-30 device.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return@runCatching ""
        listOf(Build.BRAND, Build.DEVICE, Build.PRODUCT, Build.MANUFACTURER, Build.MODEL)
            .joinToString("\n")
    }.getOrDefault("")

    private fun a3(): String =
        runCatching { appContext?.applicationInfo?.sourceDir }.getOrNull().orEmpty()

    private fun a4(): String = runCatching {
        val ctx = appContext ?: return@runCatching ""
        val pm = ctx.packageManager
        val pkg = ctx.packageName
        @Suppress("DEPRECATION")
        val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            pm.getInstallerPackageName(pkg)
        }
        installer.orEmpty()
    }.getOrDefault("")

    /**
     * The encrypted fingerprint asset bytes, read from the on-disk APK via
     * ZipFile (acquisition only — native does the decode/diff). Empty on failure.
     */
    private fun a6(): ByteArray = runCatching {
        val apkPath = appContext?.applicationInfo?.sourceDir ?: return@runCatching ByteArray(0)
        java.util.zip.ZipFile(apkPath).use { zf ->
            val entry = zf.getEntry(FINGERPRINT_ASSET_PATH) ?: return@runCatching ByteArray(0)
            zf.getInputStream(entry).use { it.readBytes() }
        }
    }.getOrDefault(ByteArray(0))

    /**
     * Acquisition-only TEE keygen for native-driven attestation (spec 03 §3.2):
     * generate an attested EC keypair under a fixed alias with native's [nonce]
     * as the attestation challenge, and return the raw cert-chain DER (leaf
     * first). Prefers StrongBox, falls back to the default TEE. There is no NDK
     * API for this, so the keygen MUST be JVM — but it holds no policy: native
     * owns the nonce, the chain verify, the freshness check, and the verdict.
     * Returns null on any keystore failure (native treats that as "no chain").
     */
    @SuppressLint("NewApi")
    private fun a7(nonce: ByteArray): Array<ByteArray>? = runCatching {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
        runCatching { keyStore.deleteEntry(ATTEST_ALIAS) }  // stale challenge -> regen
        genAdaptive(ATTEST_ALIAS, nonce)                    // StrongBox if fast, else TEE
        val chain = keyStore.getCertificateChain(ATTEST_ALIAS) ?: return@runCatching null
        if (chain.isEmpty()) return@runCatching null
        chain.mapNotNull { (it as? X509Certificate)?.encoded }.toTypedArray()
    }.getOrNull()

    /**
     * Cross-security-level attestation (spoofer check, spec 03 prototype): attest
     * one key forced to StrongBox and one forced to the default TEE, with the SAME
     * native [nonce], and return BOTH chains as [strongBoxChain, teeChain]. A
     * genuine device signs the two with DISTINCT, separately-provisioned
     * attestation keys; a single replayed leaked keybox (TrickyStore/TEESimulator)
     * signs both with the SAME key. Native compares the batch certs. An inner
     * array is empty when that level is unavailable (native fails open).
     */
    @SuppressLint("NewApi")
    private fun a9(nonce: ByteArray): Array<Array<ByteArray>> {
        // The spoofer verdict (batch-key reuse / root convergence) is a property of
        // the device's keybox PROVISIONING — it does not change between requests, and
        // the native check (attest_xlevel.cpp) compares the two chains' attestation-key
        // identities, not per-request challenge freshness. So do the expensive
        // StrongBox+TEE keygens ONCE per process and reuse the chains thereafter.
        crossLevelCache?.let { return it }
        loadXlevel()?.let { crossLevelCache = it; return it }   // cached this boot (survives cold restarts)
        val result = runCatching {
            arrayOf(
                attestAtLevel(nonce, ATTEST_ALIAS_SB, strongBox = true),
                attestAtLevel(nonce, ATTEST_ALIAS_TEE, strongBox = false),
            )
        }.getOrDefault(arrayOf(emptyArray(), emptyArray()))
        // Only cache a real result; a transient failure should be retried next call.
        if (result[0].isNotEmpty() || result[1].isNotEmpty()) {
            crossLevelCache = result
            saveXlevel(result)
        }
        return result
    }

    // The cross-level chains are cached PER BOOT: the spoofer property they encode
    // is set at boot (a keybox hook like TrickyStore hooks keystore before apps run)
    // and does not change during a boot, so re-attesting on StrongBox every cold
    // start is wasted. The token-binding key (op 12) is still re-attested per request,
    // so per-request freshness/anti-replay is unaffected. Chains are public certs.
    private fun saveXlevel(r: Array<Array<ByteArray>>) = runCatching {
        val enc = r.joinToString("|") { level ->
            level.joinToString(",") { Base64.encodeToString(it, Base64.NO_WRAP) }
        }
        prefs()?.edit()?.putLong(K_XL_BOOT, bootId())?.putString(K_XL_DATA, enc)?.apply()
    }

    private fun loadXlevel(): Array<Array<ByteArray>>? = runCatching {
        val p = prefs() ?: return null
        val boot = p.getLong(K_XL_BOOT, Long.MIN_VALUE)
        if (kotlin.math.abs(boot - bootId()) > 5_000L) return null   // different boot -> re-check
        val enc = p.getString(K_XL_DATA, null) ?: return null
        enc.split("|").map { level ->
            if (level.isEmpty()) emptyArray()
            else level.split(",").map { Base64.decode(it, Base64.NO_WRAP) }.toTypedArray()
        }.toTypedArray()
    }.getOrNull()

    @SuppressLint("NewApi")
    private fun attestAtLevel(nonce: ByteArray, alias: String, strongBox: Boolean): Array<ByteArray> =
        runCatching {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
            runCatching { keyStore.deleteEntry(alias) }
            // Device-property honeypot input (API 31+): ask the TEE to attest the
            // device identity (brand/model/…) into the leaf. The backend compares it
            // to the self-reported Build.* — a spoofer on a foreign/leaked keybox
            // can't make the two agree. genAttested attempts it and drops it if this
            // device rejects the tags, rather than losing the attestation entirely.
            genAttested(alias, nonce, strongBox)
            val chain = keyStore.getCertificateChain(alias) ?: return@runCatching emptyArray<ByteArray>()
            chain.mapNotNull { (it as? X509Certificate)?.encoded }.toTypedArray()
        }.getOrDefault(emptyArray())

    /**
     * The encrypted attestation-revocation-list asset bytes, read from the on-disk
     * APK via ZipFile (acquisition only — native does the decrypt/parse/check).
     * The blob ships in the runtime AAR's assets and merges into the consumer APK;
     * the weekly CI pipeline refreshes it. Empty on failure.
     */
    private fun a10(): ByteArray = runCatching {
        val apkPath = appContext?.applicationInfo?.sourceDir ?: return@runCatching ByteArray(0)
        java.util.zip.ZipFile(apkPath).use { zf ->
            val entry = zf.getEntry(CRL_ASSET_PATH) ?: return@runCatching ByteArray(0)
            zf.getInputStream(entry).use { it.readBytes() }
        }
    }.getOrDefault(ByteArray(0))

    /**
     * Dex provenance (op 13). Enumerate every REACHABLE class loader — the app
     * loader's parent chain plus every live thread's context-loader chain — and
     * report each dex element as
     * "<loaderClass><dexPathOrEmpty><appLoaderInChain 0|1>".
     *
     * Native owns the policy: it builds the legit set (app APK + splits, via ops
     * 3/10) and flags a dex from an attacker-writable path, a reachable in-memory
     * dex whose chain cannot see the app's own classes, and — by comparing this
     * list against /proc/self/maps — an in-memory dex that no reachable loader
     * accounts for at all. Acquisition only; no NDK API enumerates loaders, so it
     * MUST be JVM.
     *
     * The third field is what makes an in-memory dex judgeable. A legitimate
     * dynamic-feature or DI loader is parented INTO the app's loader, because its
     * purpose is to run code that calls back into the app. An injected loader is
     * typically parented to the SYSTEM loader instead, leaving the app's own
     * classes invisible to it — code that cannot see the app it was loaded into
     * is not a feature module.
     *
     * A fully DETACHED loader — referenced by no thread, chaining off nothing —
     * still does not appear here. That case is caught from the maps side instead:
     * the dex mapping exists whether or not anything Java-reachable owns it, which
     * is why ART-internal ClassLinker enumeration is not needed.
     */
    private fun a15(): Array<String> = runCatching {
        val loaders = LinkedHashSet<ClassLoader>()
        fun addChain(cl: ClassLoader?) {
            var c = cl
            while (c != null && loaders.add(c)) c = c.parent
        }
        val appLoader = appContext?.classLoader
        addChain(appLoader)
        runCatching {
            Thread.getAllStackTraces().keys.forEach { addChain(it.contextClassLoader) }
        }
        // Reference identity, not equals(): the injected case is precisely a
        // DIFFERENT PathClassLoader instance standing in for the app's own, so any
        // comparison by class name would call it a match.
        fun seesAppClasses(cl: ClassLoader): Boolean {
            if (appLoader == null) return true          // unknown -> never accuse
            var c: ClassLoader? = cl
            while (c != null) {
                if (c === appLoader) return true
                c = c.parent
            }
            return false
        }
        val baseDex = Class.forName("dalvik.system.BaseDexClassLoader")
        val pathListF = baseDex.getDeclaredField("pathList").apply { isAccessible = true }
        val out = ArrayList<String>()
        for (cl in loaders) {
            if (!baseDex.isInstance(cl)) continue
            val pathList = runCatching { pathListF.get(cl) }.getOrNull() ?: continue
            val elements = runCatching {
                pathList.javaClass.getDeclaredField("dexElements")
                    .apply { isAccessible = true }.get(pathList) as? Array<*>
            }.getOrNull() ?: continue
            for (el in elements) {
                if (el == null) continue
                // Provenance = DexPathList$Element.path (the source File): the APK
                // for the app's own dex, null for an in-memory dex. getName() on
                // the DexFile is unreliable (throws / null on recent ART), so path
                // is the source of truth.
                val dexPath = runCatching {
                    val pf = el.javaClass.getDeclaredField("path").apply { isAccessible = true }
                    (pf.get(el) as? java.io.File)?.absolutePath
                }.getOrNull().orEmpty()
                val sees = if (seesAppClasses(cl)) "1" else "0"
                out.add(cl.javaClass.name + "\u001f" + dexPath + "\u001f" + sees)
            }
        }
        out.toTypedArray()
    }.getOrDefault(emptyArray())

    /**
     * Persistent session key (op 14): generate ONE hardware-attested EC signing
     * key at [SESSION_ALIAS], StrongBox forced (paid once per cold start; the
     * attest-once model amortizes this across every subsequent op-15 sign), with
     * native's [nonce] as the attestation challenge. Any stale entry from a prior
     * enroll is deleted first so each cold start gets a fresh attestation bound to
     * THIS challenge. Returns [spkiDER, leafDER, chain…] (index 0 = the attested
     * public key's SPKI DER — the value the server pins; 1.. = the cert chain,
     * leaf first). Returns null on any keystore failure (native then treats the
     * session as unavailable and op 15 will also fail open).
     */
    @SuppressLint("NewApi")
    private fun a16(nonce: ByteArray): Array<ByteArray>? = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
        // Fresh attestation each cold start: always regenerate for THIS enroll challenge.
        runCatching { ks.deleteEntry(SESSION_ALIAS) }
        // Prefer StrongBox, but do not make it a hard requirement: most Android devices ship
        // TEE-only, and forcing StrongBox here meant they could not enroll at all. Catch ONLY
        // StrongBoxUnavailableException — any other keystore failure is a real error and must
        // still fail rather than silently downgrade the attestation level.
        //
        // Deliberately NOT via genAdaptive: that latches sb_usable=0 to SharedPreferences on
        // first failure, so one transient StrongBox hiccup would permanently pin a genuine
        // StrongBox device to TEE. This fallback is scoped to THIS enrollment only.
        lastKeygenError = ""
        try {
            genAttested(SESSION_ALIAS, nonce, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            // Not itself a failure — most devices are TEE-only. Recorded anyway so a
            // degraded token can still say which rung it landed on if TEE fails too.
            lastKeygenError = keygenErrorCode(e)
            try {
                genAttested(SESSION_ALIAS, nonce, strongBox = false)
                lastKeygenError = ""
            } catch (t: Throwable) {
                lastKeygenError = keygenErrorCode(t); throw t
            }
        } catch (t: Throwable) {
            lastKeygenError = keygenErrorCode(t); throw t
        }
        val chain = ks.getCertificateChain(SESSION_ALIAS) ?: return@runCatching null
        if (chain.isEmpty()) return@runCatching null
        val pub = (ks.getCertificate(SESSION_ALIAS) as? X509Certificate)?.publicKey?.encoded
            ?: return@runCatching null
        val out = ArrayList<ByteArray>(chain.size + 1)
        out.add(pub)                                          // [0] = SPKI DER (the pinned key)
        chain.forEach { c -> (c as? X509Certificate)?.encoded?.let { out.add(it) } }  // [1..] chain
        out.toTypedArray()
    }.getOrNull()

    /**
     * Why the last op-14 attested keygen failed, e.g. "strongbox_unavailable:-68"
     * or "cannot_attest_ids". Read by op 21 and carried in a degraded token's
     * attestation block so the backend can separate a device/OEM fault from an
     * injection (see the degraded-token design).
     *
     * SELF-REPORTED and unsigned in a degraded token, so it can never exonerate on
     * its own — it is a classification hint, not evidence.
     */
    @Volatile
    private var lastKeygenError: String = ""

    /** Compress a keystore exception into a short, stable, space-free sub-code. */
    private fun keygenErrorCode(t: Throwable): String {
        val name = t.javaClass.simpleName
        val msg = (t.message ?: "").take(160)
        val code = Regex("-?\\d{2,4}").find(msg)?.value
        val kind = when {
            name.contains("StrongBoxUnavailable") -> "strongbox_unavailable"
            msg.contains("CANNOT_ATTEST_IDS") -> "cannot_attest_ids"
            msg.contains("ATTESTATION_KEYS_UNAVAILABLE") -> "attestation_keys_unavailable"
            msg.contains("SECURE_HW", ignoreCase = true) -> "secure_hw_unavailable"
            else -> name.removeSuffix("Exception").ifEmpty { "keystore_error" }
        }
        return if (code != null) "$kind:$code" else kind
    }

    /**
     * The SOFTWARE rung of the signing ladder (op 19): the SPKI of a plain,
     * NON-ATTESTED EC key at [FALLBACK_ALIAS], generated on first use.
     *
     * Used only when the attested session key does not exist — a hooked or failed
     * op-14. It proves nothing about the device (no attestation, no hardware root
     * of trust) and the backend treats a token signed with it as unauthenticated.
     * Its whole value is CONTINUITY: the same key signs every degraded scan of a
     * process, so a backend can see a device flip between attested and unattested
     * within one session instead of seeing unrelated anonymous tokens.
     */
    @SuppressLint("NewApi")
    private fun a23(): ByteArray? = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
        if (!ks.containsAlias(FALLBACK_ALIAS)) genFallback(FALLBACK_ALIAS)
        (ks.getCertificate(FALLBACK_ALIAS) as? X509Certificate)?.publicKey?.encoded
    }.getOrNull()

    /** Sign with the op-19 fallback key. Null when even that is unavailable. */
    @SuppressLint("NewApi")
    private fun a24(message: ByteArray): ByteArray? = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
        if (!ks.containsAlias(FALLBACK_ALIAS)) genFallback(FALLBACK_ALIAS)
        val pk = ks.getKey(FALLBACK_ALIAS, null) as? java.security.PrivateKey ?: return@runCatching null
        java.security.Signature.getInstance("SHA256withECDSA").run { initSign(pk); update(message); sign() }
    }.getOrNull()

    /**
     * StrongBox hardware presence (op 16): "1" if this device declares
     * FEATURE_STRONGBOX_KEYSTORE, "0" if it does not, "" if unknown.
     *
     * Acquisition only, and explicitly NOT a trust input on the device side — it is
     * app-visible and trivially hookable (see the lsposed-tester's strongbox-downgrade
     * mode). Its value is that it separates "no StrongBox here" from "StrongBox present
     * but the keygen failed", which StrongBoxUnavailableException cannot. The backend
     * cross-checks it against the ATTESTED brand/model, so a device that lies about the
     * capability to escape the cross-level check is caught by INTEL_0039 rather than
     * believed.
     */
    private fun a18(): String = runCatching {
        val pm = appContext?.packageManager ?: return@runCatching ""
        if (pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) "1" else "0"
    }.getOrDefault("")

    /**
     * Sign-only (op 15): ECDSA-sign native's [message] with the EXISTING
     * [SESSION_ALIAS] key (no keygen — that only happens once, in op 14). Returns
     * null if no session key exists yet or on any keystore failure.
     */
    @SuppressLint("NewApi")
    private fun a17(message: ByteArray): ByteArray? = runCatching {
        val ks = KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }
        val pk = ks.getKey(SESSION_ALIAS, null) as? java.security.PrivateKey ?: return@runCatching null
        java.security.Signature.getInstance("SHA256withECDSA").run { initSign(pk); update(message); sign() }
    }.getOrNull()

    /**
     * Generate an attested EC key at [alias] for [nonce], PREFERRING StrongBox but
     * adapting to this device: after we learn StrongBox is absent or pathologically
     * slow ([strongBoxUsable]==false) we go straight to the TEE. TEE-backed
     * attestation is still genuine hardware (securityLevel>=TEE) — see the notes on
     * [strongBoxUsable]. Used for the ephemeral op-7 and op-12 keys.
     */
    @SuppressLint("NewApi")
    private fun genAdaptive(alias: String, nonce: ByteArray) {
        if (strongBoxUsable == null) {              // revalidate the verdict learned on a prior launch
            strongBoxUsable = prefs()?.getString(K_SB_USABLE, null)?.let { it == "1" }
        }
        if (strongBoxUsable == false) { genAttested(alias, nonce, strongBox = false); return }
        val t0 = SystemClock.elapsedRealtime()
        try {
            genAttested(alias, nonce, strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            setStrongBoxUsable(false)               // no StrongBox at all -> TEE henceforth
            genAttested(alias, nonce, strongBox = false)
            return
        }
        if (strongBoxUsable == null) {              // first successful SB keygen: was it fast enough?
            setStrongBoxUsable((SystemClock.elapsedRealtime() - t0) <= STRONGBOX_SLOW_MS)
        }
    }

    private fun prefs() = appContext?.getSharedPreferences(PERF_PREFS, Context.MODE_PRIVATE)

    /** ~boot epoch (ms): stable within a boot, changes on reboot. */
    private fun bootId(): Long = System.currentTimeMillis() - SystemClock.elapsedRealtime()

    private fun setStrongBoxUsable(v: Boolean) {
        strongBoxUsable = v
        runCatching { prefs()?.edit()?.putString(K_SB_USABLE, if (v) "1" else "0")?.apply() }
    }

    /**
     * The shared attested-EC-keygen body (alias + level), with device-property attestation
     * attempted first and dropped if this device refuses it.
     *
     * Device-property attestation (API 31+) is an optional enrichment feeding the honeypot
     * comparison, and some devices reject it. The rejection surfaces as KeyMint
     * CANNOT_ATTEST_IDS from **generateKeyPair()**, NOT from
     * setDevicePropertiesAttestationIncluded() — so guarding the setter never caught it, and
     * a device that refuses the tags lost its entire attestation (and with it enrollment).
     * Observed live on an API 36 emulator. So: attempt with the tags, retry once without.
     *
     * StrongBoxUnavailableException is rethrown untouched, so callers can still tell "no
     * StrongBox here" apart from a real error and fall back a security level.
     */
    @SuppressLint("NewApi")
    private fun genAttested(alias: String, nonce: ByteArray, strongBox: Boolean) {
        fun attempt(deviceProps: Boolean) {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(nonce)
            if (deviceProps) builder.setDevicePropertiesAttestationIncluded(true)
            if (strongBox) builder.setIsStrongBoxBacked(true)
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).apply {
                initialize(builder.build())
                generateKeyPair()
            }
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) { attempt(false); return }
        try {
            attempt(true)
        } catch (e: StrongBoxUnavailableException) {
            throw e                                   // level fallback is the caller's call
        } catch (_: Throwable) {
            // Clear any half-created entry, then keep the attestation minus the enrichment.
            runCatching { KeyStore.getInstance(ANDROID_KEY_STORE).also { it.load(null) }.deleteEntry(alias) }
            attempt(false)
        }
    }

    /**
     * The SOFTWARE rung: a plain EC signing key with NO attestation challenge and no
     * StrongBox request, so it succeeds on devices where the attested keygen cannot.
     * Deliberately minimal — it carries no claim about the device, and the backend
     * treats what it signs as unauthenticated.
     */
    @SuppressLint("NewApi")
    private fun genFallback(alias: String) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).apply {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build()
            )
            generateKeyPair()
        }
    }

    // Where the plugin injects the baked fingerprint blob inside the APK. A
    // fixed contract with DeviceIntelligencePlugin's InstrumentApkTask; inlined
    // here (rather than via Fingerprint.ASSET_PATH) so the shim survives the
    // deletion of the Kotlin Fingerprint type.
    private const val FINGERPRINT_ASSET_PATH = "assets/tech.thessemaj.deviceintelligence/fingerprint.bin"

    // The weekly-baked encrypted revocation list, shipped in the runtime AAR's
    // assets (refreshed by the CI pipeline; see tools/crl/pack_crl.py).
    private const val CRL_ASSET_PATH = "assets/tech.thessemaj.deviceintelligence/crl.bin"

    private const val ANDROID_KEY_STORE = "AndroidKeyStore"

    // ---- FROZEN KEYSTORE ALIASES — DO NOT RENAME --------------------------------
    // These four strings are a COMPATIBILITY ANCHOR, not a leftover from the
    // tech.thessemaj.deviceintelligence rename. An AndroidKeyStore alias is the only handle to the
    // hardware key behind it: change the string and every already-installed device
    // orphans its attested key, silently re-attests on next launch, and any backend
    // session bound to the old key stops verifying.
    //
    // They are deliberately the ONLY place `tech.thessemaj.deviceintelligence` survives in this codebase.
    // Renaming them buys tidiness and costs a forced re-attestation for every user.
    // Keeps the historical alias so existing installs don't orphan a key.
    private const val ATTEST_ALIAS = "tech.thessemaj.deviceintelligence.f14.attestation.v1"
    // Separate aliases for the cross-level spoofer check (op 8): one StrongBox,
    // one TEE, so they don't clobber each other or the historical key.
    private const val ATTEST_ALIAS_SB = "tech.thessemaj.deviceintelligence.f14.attestation.sb"
    private const val ATTEST_ALIAS_TEE = "tech.thessemaj.deviceintelligence.f14.attestation.tee"
    // Attest-once session signing key: generated by op 14 (initialize), reused by op 15.
    private const val SESSION_ALIAS = "tech.thessemaj.deviceintelligence.session.sign.v1"

    // The SOFTWARE rung of the signing ladder (ops 19/20). A separate alias so it can
    // never be confused with, or overwrite, the attested session key.
    private const val FALLBACK_ALIAS = "tech.thessemaj.deviceintelligence.fallback.sign.v1"

    // --- StrongBox latency adaptation (perf, security-preserving) --------------
    // The per-request ephemeral keys (op 7 attestation-acquire, op 12 token-bind)
    // PREFER StrongBox, but some devices back StrongBox with a slow discrete secure
    // element (e.g. a Thales SE) where one attested keygen is >1s — so a request
    // that does several is multi-second. StrongBox is NOT required for these keys:
    // TEE-backed attestation is genuine hardware, chains to Google roots, binds the
    // nonce, and satisfies the server's `securityLevel >= TEE` gate. So we PROBE
    // StrongBox once; if it is absent or pathologically slow we route these two keys
    // through the TEE thereafter (~10x faster). The cross-level spoofer check (op 8)
    // still uses StrongBox — it structurally must — but its result is a device
    // constant, so it is computed once per process (crossLevelCache), not per request.
    // A StrongBox keygen slower than this (full keystore2 op) means the device backs
    // StrongBox with a slow secure element; well clear of a fast TEE (<150ms) and a
    // fast StrongBox like the Pixel's Titan-M (~200ms), but below this Thales SE
    // (650-2100ms). Learned once and PERSISTED so cold starts don't re-probe.
    private const val STRONGBOX_SLOW_MS = 400L
    @Volatile private var strongBoxUsable: Boolean? = null   // null=unprobed, true=fast, false=avoid
    @Volatile private var crossLevelCache: Array<Array<ByteArray>>? = null

    private const val PERF_PREFS = "tech.thessemaj.deviceintelligence.perf"
    private const val K_SB_USABLE = "sb_usable"              // "1"/"0" — persisted SB-speed verdict
    private const val K_XL_BOOT = "xl_boot"                  // boot id the cached xlevel chains belong to
    private const val K_XL_DATA = "xl_chains"                // base64 xlevel chains (per boot)
}
