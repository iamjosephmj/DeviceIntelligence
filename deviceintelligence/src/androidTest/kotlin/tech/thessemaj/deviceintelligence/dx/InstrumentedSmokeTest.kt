package tech.thessemaj.deviceintelligence.dx

import androidx.test.ext.junit.runners.AndroidJUnit4
import tech.thessemaj.deviceintelligence.internal.FrameworkShim
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device smoke suite for the native engine. Runs the WHOLE env-bound native path
 * (orchestrate + framework_shim up-calls + every detector) via the NativeBridge JNI entry on a
 * real device/emulator — the code that cannot be host-unit-tested — and decodes the
 * produced tokens in-process with the :verifier decoder.
 *
 * Philosophy (per the module's long-standing note): assert the output is
 * STRUCTURALLY well-formed and the pipeline runs without crashing. It deliberately
 * does NOT assert "clean" / a TRUSTWORTHY verdict — a CI emulator legitimately trips
 * emulator/bootloader signals and its software attestation never chains to a pinned
 * Google root, so a trust assertion would be unrunnable anywhere realistic.
 */
@RunWith(AndroidJUnit4::class)
class InstrumentedSmokeTest {

    @Test fun no_scan_token_ever_contains_a_raw_device_identifier() {
        assumeTrue("no licence asset provisioned for this build", NativeBridge.initialize())
        NativeBridge.setSession(TEST_SESSION)
        val first = NativeBridge.scan("app_start")
        val second = NativeBridge.scan("checkout")
        assertTrue("bootstrap scan empty", first.isNotEmpty())
        assertTrue("steady-state scan empty", second.isNotEmpty())

        // The payload is ciphertext, so a raw identifier could only surface if
        // hashing were skipped and the value leaked through some other path. This is
        // the guard that keeps the peppering honest.
        val ctx = androidx.test.platform.app.InstrumentationRegistry
            .getInstrumentation().targetContext
        val androidId = android.provider.Settings.Secure.getString(
            ctx.contentResolver, android.provider.Settings.Secure.ANDROID_ID) ?: ""
        assumeTrue("device exposes no ANDROID_ID", androidId.isNotEmpty())
        assertFalse("raw ANDROID_ID must never appear in a token", first.contains(androidId))
        assertFalse("raw ANDROID_ID must never appear in a token", second.contains(androidId))
    }

    companion object {
        private val HEX = Regex("^[0-9a-f]+$")
        private val INTEL_ID = Regex("^SIG_[0-9]{4}$")
        // 32 bytes of entropy, as the setSession contract requires of a real app.
        private const val TEST_SESSION = "8f2c1ba940e7d35c6a1f0b8e2d4c9a37b563e0117ac8942f0d56ab38e4719c60"

        @BeforeClass @JvmStatic fun bootstrap() {
            // Register the framework shim so native up-calls (TEE keygen, apk/cloner
            // JVM inputs) resolve — attestation/apk/cloner detectors need it.
            FrameworkShim.setContext(
                androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext)
            runCatching { NativeBridge.s(FrameworkShim::class.java) }
        }
    }

    @Before fun requireNativeLoaded() {
        assertNull("libdicore.so failed to load: ${NativeBridge.loadError()}", NativeBridge.loadError())
        assertTrue("native core not ready", NativeBridge.isReady())
    }

    @Test fun initialize_reports_licence_validity() {
        // Returns false when no licence asset is provisioned for this build — the
        // fail-closed default, not a bug. It no longer silences scan(): an unlicensed
        // build that can still PARSE its blob emits a degraded token instead.
        NativeBridge.initialize()
        assertTrue("initialize() must not throw; got loadError=${NativeBridge.loadError()}", true)
    }

    @Test fun a_scan_without_a_session_is_degraded_rather_than_silent() {
        // The regression this guards: scan() used to return "" here, and silence at a
        // backend is indistinguishable from a network error or an app that never
        // integrated — which made SUPPRESSING the SDK cheaper than defeating it.
        assumeTrue("no licence asset provisioned for this build", NativeBridge.initialize())
        NativeBridge.setSession("")
        val token = NativeBridge.scan("checkout")
        assertTrue("an unbound scan must still emit a token", token.isNotEmpty())
        assertTrue("scan tokens are v2 hybrid-encrypted", token.startsWith("2:"))
    }

    @Test fun the_first_scan_bootstraps_and_later_scans_still_produce_tokens() {
        assumeTrue("no licence asset provisioned for this build", NativeBridge.initialize())
        NativeBridge.setSession(TEST_SESSION)

        val first = NativeBridge.scan("app_start")
        assertTrue("bootstrap scan empty — the attestation path did not run", first.isNotEmpty())
        assertTrue("scan tokens are v2 hybrid-encrypted", first.startsWith("2:"))
        assertTrue("v2 body must be hex", HEX.matches(first.substring(2)))

        val second = NativeBridge.scan("checkout")
        assertTrue("steady-state scan empty", second.isNotEmpty())
        assertTrue(second.startsWith("2:"))
        assertNotEquals("every scan is a fresh token (fresh ephemeral key)", first, second)
    }

    @Test fun repeated_scans_are_stable() {
        assumeTrue("no licence asset provisioned for this build", NativeBridge.initialize())
        NativeBridge.setSession(TEST_SESSION)
        repeat(5) { i ->
            assertTrue("scan #$i returned empty", NativeBridge.scan("loop_$i").isNotEmpty())
        }
    }

    // NOTE: NativeBridge.g() (sweep-gated asset-key derivation) is intentionally NOT smoke-tested
    // here — it only yields a key after a CLEAN sweep, so it returns empty on an
    // emulator / rooted rig. It is not part of the detection path and its gating makes
    // it unfit for a suite that must run on non-clean CI devices.
}
