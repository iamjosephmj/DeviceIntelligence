package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VerifierTest {

    // XOR keystream is its own inverse, so "encrypt" == decrypt over the plaintext.
    private fun tokenOf(plain: String): String =
        Hex.encode(Keystream.decrypt(plain.toByteArray(Charsets.UTF_8)))

    private val syntheticSigned = """
        {"schemaVersion":2,"point":"app_start","ts":1787220000,"nonce":"",
        "device":{"api":37,"abi":"arm64-v8a","model":"TestRig"},
        "signals":[{"id":"INTEL_0018","severity":"CRITICAL","detail":"enforce=0"},
        {"id":"INTEL_0007","severity":"CRITICAL","detail":"comm=pool-frida"},
        {"id":"INTEL_0019","severity":"MEDIUM","detail":"ro.build.tags=test-keys"}]}
    """.trimIndent().replace("\n", "")

    @Test fun keystream_roundtrips() {
        val msg = "hello device-intelligence-lab"
        val cipher = Keystream.decrypt(msg.toByteArray())
        assertEquals(msg, String(Keystream.decrypt(cipher)))
    }

    @Test fun registry_bundled_loads_and_resolves() {
        val reg = SignalRegistry.bundled
        // Not a hardcoded count: the registry is APPEND-ONLY, so a literal here breaks
        // on every legitimate addition. What matters is that the bundled resource and
        // the source of truth agree, and that retired rows are excluded from both.
        assertEquals("bundled resource must match the source of truth",
            SignalRegistry.fromResource("/signals-registry.json").size, reg.size)
        assertTrue("registry must not shrink below its known floor", reg.size >= 42)
        assertEquals("attestation", reg["INTEL_0000"]?.detector)
        assertEquals("software_attested_environment", reg["INTEL_0044"]?.kind)
        assertEquals("CRITICAL", reg["INTEL_0044"]?.severity)
        assertEquals("selinux_permissive", reg["INTEL_0018"]?.kind)
        assertNull("INTEL_0031 keybox_injection is retired", reg["INTEL_0031"])
        assertNull("INTEL_0034 strongbox_downgrade_suspected is retired", reg["INTEL_0034"])
        assertEquals("keybox_cross_level_reuse", reg["INTEL_0032"]?.kind)
        assertEquals("CRITICAL", reg["INTEL_0032"]?.severity)
        assertEquals("VERY_LOW", reg["INTEL_0033"]?.severity)   // fail-closed: lower confidence
    }

    @Test fun decoder_resolves_opaque_codes() {
        val decoded = TokenDecoder().decode(tokenOf(syntheticSigned))
        assertEquals(2, decoded.schemaVersion)
        assertEquals("TestRig", decoded.device?.model)
        assertEquals(3, decoded.signals.size)
        val selinux = decoded.signals.first { it.id == "INTEL_0018" }
        assertEquals("root", selinux.detector)
        assertEquals("SELinux permissive", selinux.title)
    }

    @Test fun unbound_token_is_rejected_but_shows_signals() {
        // No --BINDING section -> not a genuine binding.
        val res = TokenVerifier().verify(tokenOf(syntheticSigned), issuedNonce = "deadbeef")
        assertEquals(Decision.REJECT, res.decision)
        assertFalse(res.authentic)
        assertTrue(res.checks.first { it.name == "binding present" }.ok.not())
        // signals still resolved + policy applied (CRITICAL blocks, MEDIUM does not)
        assertTrue(res.signals.first { it.id == "INTEL_0018" }.blocking)
        assertFalse(res.signals.first { it.id == "INTEL_0019" }.blocking)
    }

    @Test fun policy_allow_and_block_override_severity() {
        val policy = Policy(allow = setOf("INTEL_0018"), block = setOf("INTEL_0019"))
        val res = TokenVerifier(policy = policy).verify(tokenOf(syntheticSigned), "deadbeef")
        assertFalse(res.signals.first { it.id == "INTEL_0018" }.blocking)  // allow-listed CRITICAL
        assertTrue(res.signals.first { it.id == "INTEL_0019" }.blocking)   // block-listed MEDIUM
    }

    /**
     * Offline parity against a REAL token captured from the rooted Pixel 6 Pro
     * (KernelSU + TrickyStore). Python's verdict on this exact token+nonce is
     * COMPROMISED: authentic (all 6 auth checks pass) but the TEE reports
     * Unverified / unlocked, and INTEL_0000 (attestation_critical) blocks.
     * cert.verify checks the signature only, not validity dates, so the fixture
     * does not expire.
     */
    @Test fun pixel_real_token_parity_compromised() {
        val token = resource("/pixel-token.hex").trim()
        val nonce = resource("/pixel-nonce.hex").trim()
        val res = TokenVerifier().verify(token, nonce)

        assertTrue("authenticity should pass", res.authentic)
        assertFalse("TEE integrity should fail (rooted/unlocked)", res.deviceIntegrityOk)
        assertEquals(Decision.COMPROMISED, res.decision)

        val sig0 = res.signals.firstOrNull { it.id == "INTEL_0000" }
        assertNotNull("INTEL_0000 must be present", sig0)
        assertEquals("attestation", sig0!!.detector)
        assertTrue("INTEL_0000 must block", sig0.blocking)

        // spot-check the individual auth checks match the Python output
        assertTrue(res.checks.first { it.name == "binding present" }.ok)
        assertTrue(res.checks.first { it.name == "nonce matches issued" }.ok)
        assertTrue(res.checks.first { it.name == "chain -> pinned Google root" }.ok)
        assertTrue(res.checks.first { it.name == "signature over verdict" }.ok)
        assertFalse(res.checks.first { it.name == "verified boot state = Verified" }.ok)
    }

    private fun resource(path: String): String =
        VerifierTest::class.java.getResourceAsStream(path)!!.bufferedReader().use { it.readText() }

    @Test fun resolves_signal_enrichment_attributes() {
        // A device-emitted foreign-code signal with enrichment tokens in the detail.
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0035","severity":"HIGH","detail":"Injected native library. """ +
            """path=/data/adb/modules/evilmod/zygisk/arm64-v8a.so module_id=evilmod needed=liblog.so,libc.so links_hook_lib=libdobby.so"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0035" }
        assertEquals("evilmod", sig.moduleId)
        assertEquals(listOf("liblog.so", "libc.so"), sig.linkedLibraries)
        assertEquals("libdobby.so", sig.linksHookLib)
        assertEquals("/data/adb/modules/evilmod/zygisk/arm64-v8a.so", sig.path)
    }

    @Test fun resolves_got_hijack_symbol_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0036","severity":"CRITICAL","detail":"hooked function pointer. """ +
            """lib=/system/lib64/libbinder.so hooked_symbol=ioctl hooked_by=evilmod"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0036" }
        assertEquals("ioctl", sig.hookedSymbol)
        assertEquals("evilmod", sig.hookedBy)
    }
    @Test fun resolves_libc_inline_hook_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0038","severity":"CRITICAL","detail":"inline hook. """ +
            """hooked_symbol=openat hooked_by=evilmod target=0x708ea1e000"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0038" }
        assertEquals("openat", sig.hookedSymbol)
        assertEquals("evilmod", sig.hookedBy)
        assertEquals("0x708ea1e000", sig.attributes["target"])
    }
    @Test fun resolves_libc_inline_stub_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0039","severity":"HIGH","detail":"trampoline stub. """ +
            """hooked_symbol=openat target=0x7111d38000"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0039" }
        assertEquals("openat", sig.hookedSymbol)
        assertEquals("0x7111d38000", sig.attributes["target"])
    }
    @Test fun resolves_syscall_divergence_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0040","severity":"HIGH","detail":"faccessat lies. """ +
            """hooked_symbol=faccessat path=/system/bin/sh"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0040" }
        assertEquals("faccessat", sig.hookedSymbol)
        assertEquals("/system/bin/sh", sig.path)
    }
    @Test fun correlates_definitive_hook_structural_plus_behavioral() {
        val doc = Json.parseObject(
            """{"signals":[""" +
            """{"id":"INTEL_0038","severity":"CRITICAL","detail":"inline hook. hooked_symbol=faccessat hooked_by=evilmod"},""" +
            """{"id":"INTEL_0040","severity":"HIGH","detail":"lie. hooked_symbol=faccessat path=/system/bin/sh"},""" +
            """{"id":"INTEL_0038","severity":"CRITICAL","detail":"inline hook. hooked_symbol=openat hooked_by=evilmod"}""" +
            """]}"""
        )
        val sigs = Signals.resolve(doc, SignalRegistry.bundled, Policy())
        val vr = VerificationResult(Decision.COMPROMISED, true, false, emptyList(), 3, null, null, null, null, sigs)
        // faccessat has BOTH structural (0038) and behavioral (0040); openat has only structural.
        assertEquals(listOf("faccessat"), vr.definitiveHooks)
    }
    @Test fun resolves_linker_maps_divergence_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0041","severity":"HIGH","detail":"map spoof. """ +
            """object=/data/adb/modules/x/libzygisk.so base=0x7ab00000"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0041" }
        assertEquals("/data/adb/modules/x/libzygisk.so", sig.attributes["object"])
        assertEquals("0x7ab00000", sig.attributes["base"])
    }
    @Test fun resolves_sealed_exec_memfd_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0042","severity":"HIGH","detail":"sealed memfd. """ +
            """object=/memfd:jit-cache seals=0xf"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0042" }
        assertEquals("/memfd:jit-cache", sig.attributes["object"])
        assertEquals("0xf", sig.attributes["seals"])
    }
    @Test fun resolves_property_divergence_attributes() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0043","severity":"CRITICAL","detail":"prop lie. """ +
            """hooked_symbol=__system_property_get key=ro.boot.verifiedbootstate get=green area=orange"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0043" }
        assertEquals("__system_property_get", sig.hookedSymbol)
        assertEquals("ro.boot.verifiedbootstate", sig.attributes["key"])
        assertEquals("green", sig.attributes["get"])
        assertEquals("orange", sig.attributes["area"])
    }

    // ── INTEL_0009 hook_stub_regions policy fold ────────────────────────────────

    @Test fun resolves_rwx_hook_stub_regions_and_confirmed_pool() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0009","severity":"CRITICAL","detail":"rwx. """ +
            """region_count=4 hook_stub_regions=1 region_3=705d852000-705d859000 [anon] stubs=6 tramp=legit"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0009" }
        assertEquals(1, sig.hookStubRegions)
        assertTrue("stubs branch into real code -> confirmed hook pool", sig.isConfirmedHookPool)
        assertTrue("default policy: confirmed pool blocks", sig.blocking)
    }

    @Test fun rwx_bare_no_hook_stubs_is_not_a_confirmed_pool() {
        val doc = Json.parseObject(
            """{"signals":[{"id":"INTEL_0009","severity":"CRITICAL","detail":"rwx. """ +
            """region_count=2 hook_stub_regions=0 region_0=aaaa-bbbb [anon] stubs=0 tramp=none"}]}"""
        )
        val sig = Signals.resolve(doc, SignalRegistry.bundled, Policy()).first { it.id == "INTEL_0009" }
        assertEquals(0, sig.hookStubRegions)
        assertFalse("no hook stubs -> not a confirmed pool (possibly a JIT cache)", sig.isConfirmedHookPool)
        assertTrue("default policy unchanged: bare RWX still blocks on CRITICAL", sig.blocking)
    }

    @Test fun confirmed_hook_pool_blocks_even_when_critical_relaxed() {
        // A confirmed hook pool must block regardless of severity tuning.
        val p = Policy(blockSeverities = emptySet())
        assertTrue(p.isBlocking("INTEL_0009", "CRITICAL", "rwx_memory_mapping", 1))
        assertFalse("bare RWX no longer blocks once CRITICAL is not a block severity",
            p.isBlocking("INTEL_0009", "CRITICAL", "rwx_memory_mapping", 0))
    }

    @Test fun observe_unconfirmed_rwx_downgrades_bare_rwx_only() {
        val p = Policy(observeUnconfirmedRwx = true)
        assertFalse("opt-in: bare RWX (hook_stub_regions=0) is observed, not blocked",
            p.isBlocking("INTEL_0009", "CRITICAL", "rwx_memory_mapping", 0))
        assertTrue("confirmed hook pool still blocks under the flag",
            p.isBlocking("INTEL_0009", "CRITICAL", "rwx_memory_mapping", 2))
        assertTrue("the flag does not affect other CRITICAL signals",
            p.isBlocking("INTEL_0018", "CRITICAL", "selinux_permissive", null))
    }

    @Test fun verification_result_surfaces_confirmed_hook_pools() {
        val doc = Json.parseObject(
            """{"signals":[""" +
            """{"id":"INTEL_0009","severity":"CRITICAL","detail":"rwx. hook_stub_regions=2"},""" +
            """{"id":"INTEL_0018","severity":"CRITICAL","detail":"enforce=0"}]}"""
        )
        val signals = Signals.resolve(doc, SignalRegistry.bundled, Policy())
        val vr = VerificationResult(Decision.COMPROMISED, true, false, emptyList(),
            2, "app_start", 0L, null, null, signals)
        assertEquals(1, vr.confirmedHookPools.size)
        assertEquals("INTEL_0009", vr.confirmedHookPools.single().id)
    }
}
