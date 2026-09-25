package tech.thessemaj.deviceintelligence.dx

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import tech.thessemaj.deviceintelligence.internal.FrameworkShim
import tech.thessemaj.deviceintelligence.verifier.ScanSession
import tech.thessemaj.deviceintelligence.verifier.ScanVerifier
import tech.thessemaj.deviceintelligence.verifier.ServerKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.security.PrivateKey
import java.util.Base64

/**
 * Clean-device baseline — the expected profile of a GENUINE, unrooted device, and
 * the only place the device and the backend are checked against each other on real
 * hardware: the token this device produces is verified by the real [ScanVerifier],
 * using the private half of the dev licence key shipped in androidTest assets.
 *
 * Must NOT run on the CI emulator (trips emulator signals) or the rooted spoofing
 * Pixel, so it is gated behind the `expectClean` instrumentation arg and SKIPS
 * (via assume) otherwise:
 *   ./gradlew :deviceintelligence:connectedDebugAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=tech.thessemaj.deviceintelligence.dx.CleanDeviceTest \
 *     -Pandroid.testInstrumentationRunnerArguments.expectClean=true
 */
// Method order is FIXED and load-bearing: only the FIRST scan of a process
// bootstraps (the attested key is bound to the session and outlives the test
// method), so the bootstrap assertions must run first or they never run at all.
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@RunWith(AndroidJUnit4::class)
class CleanDeviceTest {

    // 32 bytes of entropy, as the setSession contract requires of a real integration.
    private val sessionId = "8f2c1ba940e7d35c6a1f0b8e2d4c9a37b563e0117ac8942f0d56ab38e4719c60"

    // Detectors whose findings mean the device is compromised/instrumented — none may
    // fire on a genuine clean device. (apk/dex self-integrity are excluded: a debug
    // androidTest build legitimately differs from the released fingerprint.)
    private val COMPROMISE =
        setOf("root", "self_hook", "art", "native", "environment", "seccomp", "attestation")

    private lateinit var priv: PrivateKey

    private companion object {
        // The attested key survives the process, so the binding does too.
        var bound: ScanSession? = null
    }

    @Before fun onlyOnDeclaredCleanDevice() {
        val expect = InstrumentationRegistry.getArguments().getString("expectClean")
        assumeTrue("pass -P...expectClean=true on a genuine clean device to run this", expect == "true")
        // A real app does both at bootstrap: register the shim class for native
        // up-calls, and hand it a Context. Without the Context the shim cannot read
        // the signing certificate or persist which session the attested key belongs
        // to, so the self-report is empty and every scan re-bootstraps.
        FrameworkShim.setContext(InstrumentationRegistry.getInstrumentation().targetContext)
        runCatching { NativeBridge.s(FrameworkShim::class.java) }
        priv = readDevKey()
        assumeTrue("no licence asset provisioned for this build", NativeBridge.initialize())
        NativeBridge.setSession(sessionId)
    }

    /**
     * The bootstrap scan attests to hardware, chains to a pinned Google root, and its
     * attestation challenge is the session id — the binding that makes a captured scan
     * useless against any other session.
     */
    @Test fun t1_bootstrap_scan_verifies_to_pinned_google_root() {
        val token = NativeBridge.scan("app_start")
        assertTrue("bootstrap scan empty", token.isNotEmpty())
        assertTrue("scan tokens are v2 hybrid-encrypted", token.startsWith("2:"))

        val r = ScanVerifier().verifyScan(token, sessionId, priv)
        assertTrue("clean device bootstrap must verify but failed: ${r.reason}", r.ok)
        assertTrue("must be the bootstrap scan", r.bootstrap)
        assertNotNull("bootstrap must hand back a key to bind to the session", r.attestedKey)
        assertTrue(r.checks.first { it.name == "chain -> pinned Google root" }.ok)
        assertTrue(r.checks.first { it.name == "attestation challenge == session id" }.ok)
        assertNotNull("a real leaf must carry attestationApplicationId (tag 709)", r.attestedApp)
        bound = r.session
    }

    /**
     * The steady-state scan is signed by the key bootstrap attested, and its
     * self-reported identity agrees with what the TEE attested — so no INTEL_0046.
     */
    @Test fun t2_steady_state_scan_verifies_against_the_bootstrap_key() {
        val boot = ensureBound()
        val r = ScanVerifier().verifyScan(
            NativeBridge.scan("checkout"), sessionId, priv,
            session = boot,
        )
        assertTrue("steady-state scan must verify but failed: ${r.reason}", r.ok)
        assertFalse("must not be a second bootstrap", r.bootstrap)
        assertTrue(r.checks.first { it.name == "signature by the bound key" }.ok)
        assertFalse("a genuine app must not raise an identity mismatch",
            r.signals.any { it.id == "INTEL_0046" })
    }

    /** A token signed by this device must not verify against somebody else's key. */
    @Test fun t3_scan_does_not_verify_against_the_wrong_bound_key() {
        ensureBound()
        val r = ScanVerifier().verifyScan(
            NativeBridge.scan("checkout"), sessionId, priv,
            session = bound!!.copy(attestedKey = "00".repeat(91)))
        assertFalse("a foreign key must not verify this signature", r.ok)
    }

    /** A genuine clean device trips NO compromise detector. */
    @Test fun t4_reports_no_compromise_signals() {
        val bound = ensureBound()
        val r = ScanVerifier().verifyScan(
            NativeBridge.scan("app_start"), sessionId, priv,
            session = bound)
        assertTrue("scan failed: ${r.reason}", r.ok)

        val bad = r.signals.filter { it.detector in COMPROMISE }
        Log.i("DIPROFILE", "signals=${r.signals.map { "${it.id}:${it.detector}" }}")
        assertTrue("clean device reported compromise signals: " +
            bad.joinToString { "${it.id}(${it.detector}/${it.kind})" }, bad.isEmpty())
        assertEquals("clean device should report zero signals", 0, r.signals.size)
    }

    @Test fun t5_bootstrap_carries_a_verifiable_fingerprint() {
        val bound = ensureBound()
        assertNotNull("bootstrap must surface a fingerprint", bound.fingerprint)
        val fp = bound.fingerprint!!
        assertEquals("id is a sha256 hex digest", 64, fp.id?.length)
        assertTrue("id is lowercase hex", fp.id!!.matches(Regex("[0-9a-f]{64}")))
        assertEquals("aid is a sha256 hex digest", 64, fp.aid?.length)
        assertTrue("kernel should be readable on a real device",
            (fp.kernel ?: "").isNotEmpty())
        assertTrue("build fingerprint should be readable", (fp.build ?: "").isNotEmpty())
    }

    @Test fun t6_no_patch_mismatch_on_a_genuine_device() {
        val bound = ensureBound()
        val r = ScanVerifier().verifyScan(NativeBridge.scan("checkout"), sessionId, priv, session = bound)
        assertFalse("a genuine device must not report a patch-level mismatch",
            r.signals.any { it.id == "INTEL_0019" })
    }

    /**
     * The binding t1 established, which every steady-state scan verifies against.
     */
    private fun ensureBound(): ScanSession {
        assertNotNull("t1 must run first and record the binding", bound)
        return bound!!
    }

    /**
     * The dev licence key's private half, from androidTest assets. TEST-ONLY: it is
     * the counterpart of a blob signed with the publisher key compiled into the APK,
     * which is public by assumption. Release builds mint their own via deviceintelligenceGenerateKey.
     *
     * Returned as [PrivateKey], not XECPrivateKey: Conscrypt's OpenSSLX25519PrivateKey
     * does not implement that interface, so casting to it fails on Android.
     */
    private fun readDevKey(): PrivateKey {
        val pem = InstrumentationRegistry.getInstrumentation().context.assets
            .open("dev-backend-priv.pem").bufferedReader().use { it.readText() }
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(Regex("\\s"), "")
        // ServerKey, not KeyFactory: no XDH provider below API 33, and we test at 28.
        return ServerKey.fromPkcs8(Base64.getDecoder().decode(pem))
    }
}
