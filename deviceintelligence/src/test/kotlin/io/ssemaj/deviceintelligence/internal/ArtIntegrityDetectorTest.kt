package io.ssemaj.deviceintelligence.internal

import io.ssemaj.deviceintelligence.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for the [ArtIntegrityDetector] surface. Live
 * end-to-end ART scanning happens on-device in M4's CTF run; this
 * file pins the Kotlin-side parser + finding-emitter contract so
 * any future native-side change to the wire format produces a
 * test failure in addition to a runtime mismatch.
 */
class ArtIntegrityDetectorTest {

    private val pkg = "io.ssemaj.test"

    @Test
    fun `detector id matches the F18 contract`() {
        assertEquals("integrity.art", ArtIntegrityDetector.id)
    }

    @Test
    fun `ScanRecord parses a well-formed clean record`() {
        val r = ArtIntegrityDetector.ScanRecord.parse(
            "java.lang.Object#hashCode|0x77139d01e0|0x77139d01e0|libart|libart|1|0",
        )
        assertNotNull(r)
        r!!
        assertEquals("java.lang.Object#hashCode", r.shortId)
        assertEquals("0x77139d01e0", r.liveHex)
        assertEquals("libart", r.liveClass)
        assertTrue(r.readable)
        assertEquals(false, r.drifted)
    }

    @Test
    fun `ScanRecord returns null for malformed input`() {
        assertNull(ArtIntegrityDetector.ScanRecord.parse("not enough fields"))
        assertNull(ArtIntegrityDetector.ScanRecord.parse(""))
    }

    @Test
    fun `vectorAFindingsFromRecords ignores well-classified slots`() {
        val records = arrayOf(
            "java.lang.Object#hashCode|0x77139d01e0|0x77139d01e0|libart|libart|1|0",
            "java.lang.String#length|0x5cf44de0|0x5cf44de0|jit_cache|jit_cache|1|0",
            "java.lang.System#nanoTime|0x0|0x0|unknown|unknown|0|0", // INDEX-encoded, skipped
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords emits one out_of_range finding per unknown live class`() {
        // drifted=0 isolates the range-only path; drifted=1 + unknown
        // is exercised separately by `emits both range and drift`.
        val records = arrayOf(
            "java.lang.Object#hashCode|0xdeadbeef|0xdeadbeef|unknown|unknown|1|0",
            "java.lang.String#length|0x5cf44de0|0x5cf44de0|jit_cache|jit_cache|1|0",
            "java.lang.Math#abs(int)|0x0|0x0|unknown|unknown|0|0", // INDEX-encoded -> skip
            "java.lang.Object#getClass|0xcafebabe|0xcafebabe|unknown|unknown|1|0",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(2, findings.size)
        for (f in findings) {
            assertEquals(ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_OUT_OF_RANGE, f.kind)
            assertEquals(Severity.HIGH, f.severity)
            assertEquals(pkg, f.subject)
            assertEquals("unknown", f.details["live_classification"])
        }
        assertEquals("0xdeadbeef", findings[0].details["live_address"])
        assertEquals("java.lang.Object#hashCode", findings[0].details["method"])
        assertEquals("0xcafebabe", findings[1].details["live_address"])
        assertEquals("java.lang.Object#getClass", findings[1].details["method"])
    }

    @Test
    fun `vectorAFindingsFromRecords skips unreadable slots even with unknown live class`() {
        // INDEX-encoded jmethodIDs report live_class=unknown but
        // readable=0 — they must NOT produce findings, because we
        // simply can't tell whether they're hooked at all.
        val records = arrayOf(
            "java.lang.System#currentTimeMillis|0x0|0x0|unknown|unknown|0|0",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords suppresses drift when both snapshot and live are libart`() {
        // Real-world: at JNI_OnLoad, ART installs `art_quick_to_interpreter_bridge`
        // (and similar lazy-resolution stubs) as the entry of many JDK
        // methods. The first time the method is called, ART resolves it
        // to its AOT-compiled body — which often also lives inside
        // libart's RX segment, just at a different address. The drift
        // is real (addresses differ) but benign — so we suppress it to
        // avoid false positives on every long-running app.
        val records = arrayOf(
            "java.lang.Object#hashCode|0x77139d0070|0x77139d01e0|libart|libart|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords emits drift finding when snapshot was libart and live escaped`() {
        // Hook redirected the entry to a Frida-allocated trampoline
        // page (live_class=unknown). out_of_range will also fire
        // independently; this test asserts drift fires too — both
        // are independent attacker-driven signals.
        val records = arrayOf(
            "java.lang.Object#hashCode|0xdeadbeef|0x77139d01e0|unknown|libart|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        // Two findings: out_of_range AND drifted — both derive from
        // the same record because they answer different questions
        // ("currently hooked" vs "drifted since startup").
        assertEquals(2, findings.size)
        val drift = findings.single { it.kind == ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_DRIFTED }
        assertEquals(Severity.HIGH, drift.severity)
        assertEquals("java.lang.Object#hashCode", drift.details["method"])
        assertEquals("0xdeadbeef", drift.details["live_address"])
        assertEquals("0x77139d01e0", drift.details["snapshot_address"])
    }

    @Test
    fun `vectorAFindingsFromRecords emits drift finding when snapshot was boot_oat`() {
        val records = arrayOf(
            "java.lang.String#length|0x77139d0070|0x724f5000|libart|boot_oat|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_DRIFTED, findings[0].kind)
    }

    @Test
    fun `vectorAFindingsFromRecords suppresses drift WITHIN JIT cache`() {
        // ART can re-JIT-compile a method at a higher tier, and
        // the new entry usually lands elsewhere in the JIT cache.
        // String.length is a stable example of this — its entry
        // drifts within jit_cache on every cold start. We accept
        // missing Frida-Java hooks on JIT-resident non-native
        // methods at this layer (Vectors E + F catch most of
        // those cases via different fields).
        val records = arrayOf(
            "java.lang.Object#getClass|0x5cf52260|0x5cf505b0|jit_cache|jit_cache|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords emits drift on jit_cache to libart transition (Frida-Java native hook)`() {
        // Real-world: Frida-Java's `cls.hashCode.implementation = ...`
        // for a JDK-native method redirects entry_point_from_quick_compiled_code_
        // from a JIT-cache-resident body to a libart-resident JNI
        // dispatch stub. This crosses the jit_cache → libart
        // boundary, which is not a benign ART transition.
        val records = arrayOf(
            "java.lang.Object#hashCode|0x79836aa1e0|0x48026970|libart|jit_cache|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_DRIFTED, findings[0].kind)
        assertEquals("java.lang.Object#hashCode", findings[0].details["method"])
        assertEquals("libart", findings[0].details["live_classification"])
        assertEquals("jit_cache", findings[0].details["snapshot_classification"])
    }

    @Test
    fun `vectorAFindingsFromRecords suppresses libart to jit_cache lazy resolution`() {
        // ART installs `art_quick_to_interpreter_bridge` (libart)
        // initially; the first call may resolve to the JIT-compiled
        // body in jit_cache. That's benign — different region but
        // legitimate ART machinery.
        val records = arrayOf(
            "java.lang.String#charAt|0x484b0510|0x77139d01e0|jit_cache|libart|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords suppresses libart to boot_oat lazy resolution`() {
        val records = arrayOf(
            "java.lang.Object#<init>|0x720000a0|0x77139d01e0|boot_oat|libart|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords suppresses drift when snap was already unknown`() {
        // No stable baseline if the snapshot region was unknown.
        // (Live moves to libart, so out_of_range doesn't fire either —
        // pure drift-suppression test.)
        val records = arrayOf(
            "java.lang.Object#hashCode|0x77139d01e0|0x7982f08000|libart|unknown|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorAFindingsFromRecords emits both range and drift findings simultaneously`() {
        // Worst-case: hooker replaced entry with garbage AND that
        // garbage is outside known regions. Both signals fire —
        // they're independent and a backend may want to alert on
        // either separately.
        val records = arrayOf(
            "java.lang.Object#hashCode|0xdeadbeef|0x77139d01e0|unknown|libart|1|1",
        )
        val findings = ArtIntegrityDetector.vectorAFindingsFromRecords(records, pkg)
        assertEquals(2, findings.size)
        val kinds = findings.map { it.kind }.toSet()
        assertTrue(ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_OUT_OF_RANGE in kinds)
        assertTrue(ArtIntegrityDetector.KIND_ART_METHOD_ENTRY_DRIFTED in kinds)
    }

    // ---- Vector C — JNIEnv function-table tests ----

    @Test
    fun `JniEnvScanRecord parses a well-formed clean record`() {
        val r = ArtIntegrityDetector.JniEnvScanRecord.parse(
            "GetMethodID|0x77139d01e0|0x77139d01e0|libart|libart|0",
        )
        assertNotNull(r)
        r!!
        assertEquals("GetMethodID", r.functionName)
        assertEquals("0x77139d01e0", r.liveHex)
        assertEquals("0x77139d01e0", r.snapshotHex)
        assertEquals("libart", r.liveClass)
        assertEquals("libart", r.snapshotClass)
        assertEquals(false, r.drifted)
    }

    @Test
    fun `JniEnvScanRecord returns null for malformed input`() {
        assertNull(ArtIntegrityDetector.JniEnvScanRecord.parse("not enough fields"))
        assertNull(ArtIntegrityDetector.JniEnvScanRecord.parse(""))
    }

    @Test
    fun `vectorCFindingsFromRecords ignores libart-classified pointers`() {
        val records = arrayOf(
            "GetMethodID|0x77139d01e0|0x77139d01e0|libart|libart|0",
            "RegisterNatives|0x77139d0500|0x77139d0500|libart|libart|0",
        )
        val findings = ArtIntegrityDetector.vectorCFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorCFindingsFromRecords emits out_of_range when JNIEnv pointer escapes libart`() {
        // Frida-Java style: GetMethodID rewritten to point at a
        // hooker-controlled trampoline allocated via mmap (no ART
        // region match → unknown).
        val records = arrayOf(
            "GetMethodID|0xdeadbeef|0xdeadbeef|unknown|unknown|0",
            "RegisterNatives|0x77139d0500|0x77139d0500|libart|libart|0",
            "CallStaticIntMethod|0xfeedface|0xfeedface|unknown|unknown|0",
        )
        val findings = ArtIntegrityDetector.vectorCFindingsFromRecords(records, pkg)
        assertEquals(2, findings.size)
        for (f in findings) {
            assertEquals(ArtIntegrityDetector.KIND_JNI_ENV_TABLE_OUT_OF_RANGE, f.kind)
            assertEquals(Severity.HIGH, f.severity)
            assertEquals(pkg, f.subject)
            assertEquals("unknown", f.details["live_classification"])
        }
        assertEquals("GetMethodID", findings[0].details["function"])
        assertEquals("0xdeadbeef", findings[0].details["live_address"])
        assertEquals("CallStaticIntMethod", findings[1].details["function"])
    }

    @Test
    fun `vectorCFindingsFromRecords emits drift finding regardless of classification`() {
        // Unlike Vector A, we report drift even when the live
        // pointer still classifies as libart — JNINativeInterface
        // entries do not legitimately move within libart, and any
        // change implies the table was rewritten.
        val records = arrayOf(
            "GetMethodID|0x77139d0070|0x77139d01e0|libart|libart|1",
        )
        val findings = ArtIntegrityDetector.vectorCFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(ArtIntegrityDetector.KIND_JNI_ENV_TABLE_DRIFTED, findings[0].kind)
        assertEquals("GetMethodID", findings[0].details["function"])
        assertEquals("0x77139d0070", findings[0].details["live_address"])
        assertEquals("0x77139d01e0", findings[0].details["snapshot_address"])
    }

    @Test
    fun `vectorCFindingsFromRecords emits both range and drift findings simultaneously`() {
        val records = arrayOf(
            "GetMethodID|0xdeadbeef|0x77139d01e0|unknown|libart|1",
        )
        val findings = ArtIntegrityDetector.vectorCFindingsFromRecords(records, pkg)
        assertEquals(2, findings.size)
        val kinds = findings.map { it.kind }.toSet()
        assertTrue(ArtIntegrityDetector.KIND_JNI_ENV_TABLE_OUT_OF_RANGE in kinds)
        assertTrue(ArtIntegrityDetector.KIND_JNI_ENV_TABLE_DRIFTED in kinds)
    }

    // ---- Vector D — inline prologue tests ----

    @Test
    fun `InlinePrologueScanRecord parses a well-formed clean record`() {
        val r = ArtIntegrityDetector.InlinePrologueScanRecord.parse(
            "art_quick_invoke_stub|0x77139abc00" +
                "|fd7bbfa9fc6f01a9fb6702a9f967bd|fd7bbfa9fc6f01a9fb6702a9f967bd" +
                "|1|0|0|0",
        )
        assertNotNull(r)
        r!!
        assertEquals("art_quick_invoke_stub", r.symbol)
        assertEquals("0x77139abc00", r.addressHex)
        assertTrue(r.resolved)
        assertEquals(false, r.drifted)
        assertEquals(false, r.baselineKnown)
        assertEquals(false, r.baselineMismatch)
    }

    @Test
    fun `InlinePrologueScanRecord returns null for malformed input`() {
        assertNull(ArtIntegrityDetector.InlinePrologueScanRecord.parse("not enough"))
        assertNull(ArtIntegrityDetector.InlinePrologueScanRecord.parse(""))
    }

    @Test
    fun `vectorDFindingsFromRecords ignores clean and unresolved slots`() {
        val records = arrayOf(
            // clean
            "art_quick_invoke_stub|0x77139abc00|aa|aa|1|0|0|0",
            // unresolved
            "art_quick_resolution_trampoline|0x0|||0|0|0|0",
        )
        val findings = ArtIntegrityDetector.vectorDFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorDFindingsFromRecords emits drift finding when prologue changed`() {
        val records = arrayOf(
            "art_quick_invoke_stub|0x77139abc00" +
                "|f0031f04000000d4f0031f04000000d4|fd7bbfa9fc6f01a9fb6702a9f967bd00" +
                "|1|1|0|0",
        )
        val findings = ArtIntegrityDetector.vectorDFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        val f = findings[0]
        assertEquals(ArtIntegrityDetector.KIND_ART_INTERNAL_PROLOGUE_DRIFTED, f.kind)
        assertEquals(Severity.HIGH, f.severity)
        assertEquals("art_quick_invoke_stub", f.details["symbol"])
        assertEquals("0x77139abc00", f.details["address"])
    }

    @Test
    fun `vectorDFindingsFromRecords emits baseline_mismatch when known baseline differs`() {
        val records = arrayOf(
            "art_quick_invoke_stub|0x77139abc00" +
                "|f0031f04000000d4f0031f04000000d4|f0031f04000000d4f0031f04000000d4" +
                "|1|0|1|1",
        )
        val findings = ArtIntegrityDetector.vectorDFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        val f = findings[0]
        assertEquals(
            ArtIntegrityDetector.KIND_ART_INTERNAL_PROLOGUE_BASELINE_MISMATCH,
            f.kind,
        )
        assertEquals(Severity.MEDIUM, f.severity)
        assertEquals("art_quick_invoke_stub", f.details["symbol"])
    }

    @Test
    fun `vectorDFindingsFromRecords emits both drift and baseline mismatch simultaneously`() {
        val records = arrayOf(
            "art_quick_invoke_stub|0x77139abc00" +
                "|f0031f04000000d4f0031f04000000d4|fd7bbfa9fc6f01a9fb6702a9f967bd00" +
                "|1|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorDFindingsFromRecords(records, pkg)
        assertEquals(2, findings.size)
        val kinds = findings.map { it.kind }.toSet()
        assertTrue(ArtIntegrityDetector.KIND_ART_INTERNAL_PROLOGUE_DRIFTED in kinds)
        assertTrue(
            ArtIntegrityDetector.KIND_ART_INTERNAL_PROLOGUE_BASELINE_MISMATCH in kinds,
        )
    }

    @Test
    fun `vectorDFindingsFromRecords skips baseline mismatch when baseline is unknown`() {
        // baseline_known=0 must NOT produce a finding even if
        // baseline_mismatch=1 (which shouldn't happen, but the
        // emitter must defensively skip it).
        val records = arrayOf(
            "unknown_symbol|0x77139abc00|aa|aa|1|0|0|1",
        )
        val findings = ArtIntegrityDetector.vectorDFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    // ---- Vector E — entry_point_from_jni_ tests ----

    @Test
    fun `JniEntryScanRecord parses a well-formed clean record`() {
        val r = ArtIntegrityDetector.JniEntryScanRecord.parse(
            "java.lang.Object#hashCode|0x77139d01e0|0x77139d01e0|libart|libart|1|0|1",
        )
        assertNotNull(r)
        r!!
        assertEquals("java.lang.Object#hashCode", r.shortId)
        assertEquals("0x77139d01e0", r.liveHex)
        assertEquals("libart", r.liveClass)
        assertTrue(r.readable)
        assertEquals(false, r.drifted)
        assertTrue(r.isNativeBySpec)
    }

    @Test
    fun `JniEntryScanRecord returns null for malformed input`() {
        assertNull(ArtIntegrityDetector.JniEntryScanRecord.parse("not enough fields"))
        assertNull(ArtIntegrityDetector.JniEntryScanRecord.parse(""))
    }

    @Test
    fun `vectorEFindingsFromRecords ignores clean slots`() {
        val records = arrayOf(
            "java.lang.Object#hashCode|0x77139d01e0|0x77139d01e0|libart|libart|1|0|1",
            "java.lang.System#nanoTime|0x0|0x0|unknown|unknown|0|0|0", // INDEX-encoded
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorEFindingsFromRecords emits drift only on JDK-native methods`() {
        // A non-native method's `data_` slot legitimately changes
        // due to JIT profiling. Drift on a method declared
        // `native` in the JDK (registry kind == JNI_NATIVE) is
        // the canonical Frida-Java bridge-install signal — even
        // when ART has cleared the runtime ACC_NATIVE bit due to
        // intrinsification (Object#hashCode is the canonical
        // example of this on modern Android).
        val records = arrayOf(
            // Declared-native method drifted: emit drift.
            "java.lang.Object#hashCode|0xdeadbeef|0x77139d01e0|unknown|libart|1|1|1",
            // Non-native method drifted (is_native_by_spec=0): suppress.
            "java.lang.String#length|0x77139aa000|0x77139d01e0|libart|libart|1|1|0",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        val driftFindings = findings.filter {
            it.kind == ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_DRIFTED
        }
        assertEquals(1, driftFindings.size)
        assertEquals("java.lang.Object#hashCode", driftFindings[0].details["method"])
    }

    @Test
    fun `vectorEFindingsFromRecords emits out_of_range on known-to-unknown transition for non-native method`() {
        // Frida-Java attaches to a non-native method too; the
        // bridge pointer lands in unknown memory. We emit
        // out_of_range when `snap_class` was known (libart/boot_oat)
        // and `live_class` transitioned to unknown — which is the
        // canonical Frida-Java fingerprint for any method type.
        val records = arrayOf(
            "java.lang.String#length|0xfeedface|0x77139d01e0|unknown|libart|1|1|0",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(
            ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_OUT_OF_RANGE,
            findings[0].kind,
        )
        assertEquals("false", findings[0].details["is_native_by_spec"])
    }

    @Test
    fun `vectorEFindingsFromRecords suppresses out_of_range when snapshot was already unknown`() {
        // Real-world: boot-image-resolved native methods have
        // their `data_` slot pointing into the boot image
        // (`boot.art`), which our classifier doesn't know about
        // and so reads as `unknown` at snapshot time. Without
        // this filter, every such method false-positives on a
        // clean device. Frida-Java's bridge install would still
        // be caught because `drifted=1` fires on the value
        // change (and the JDK-native gate accepts it).
        val records = arrayOf(
            // snap_class=unknown (boot.art), live_class=unknown (still boot.art)
            "java.lang.Object#hashCode|0x7982f08000|0x7982f08000|unknown|unknown|1|0|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorEFindingsFromRecords emits drift even when both snapshot and live are unknown`() {
        // Frida-Java overwrites a boot.art stub pointer with its
        // own bridge — both classify as unknown, but the value
        // changed. Drift fires because is_native_by_spec=1.
        val records = arrayOf(
            "java.lang.Object#hashCode|0xfeedface|0x7982f08000|unknown|unknown|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(
            ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_DRIFTED,
            findings[0].kind,
        )
    }

    @Test
    fun `vectorEFindingsFromRecords skips unreadable slots`() {
        val records = arrayOf(
            "java.lang.System#nanoTime|0x0|0x0|unknown|unknown|0|0|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorEFindingsFromRecords emits both drift and out_of_range simultaneously on hooked native method`() {
        val records = arrayOf(
            "java.lang.Object#hashCode|0xdeadbeef|0x77139d01e0|unknown|libart|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(2, findings.size)
        val kinds = findings.map { it.kind }.toSet()
        assertTrue(ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_OUT_OF_RANGE in kinds)
        assertTrue(ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_DRIFTED in kinds)
    }

    @Test
    fun `vectorEFindingsFromRecords suppresses drift on libart-to-libart lazy bridge resolution`() {
        // HwART (and AOSP under some conditions) re-resolves a
        // declared-native method's `data_` slot from a
        // `art_jni_dlsym_lookup_*` stub to the actual JNI bridge
        // on first call. Both addresses sit inside libart's RX
        // segment — the value differs but the classification is
        // identical. This is benign ART machinery, not a
        // Frida-Java attack. Empirically observed on Huawei API
        // 31 for `Object.hashCode` and friends.
        val records = arrayOf(
            "java.lang.Object#hashCode|0x77139d0070|0x77139d01e0|libart|libart|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorEFindingsFromRecords suppresses drift on cross-region libart-boot_oat lazy resolution`() {
        // Cross-region resolution within ART memory: bridge
        // resolved from a libart stub into a boot OAT body, or
        // vice versa. Less common than libart→libart but observed
        // on some HwART / Samsung builds. Both directions are
        // benign for declared-native methods.
        val libartToBootOat = arrayOf(
            "java.lang.Object#hashCode|0x720000a0|0x77139d01e0|boot_oat|libart|1|1|1",
        )
        assertEquals(
            0,
            ArtIntegrityDetector.vectorEFindingsFromRecords(libartToBootOat, pkg).size,
        )
        val bootOatToLibart = arrayOf(
            "java.lang.Object#hashCode|0x77139d0070|0x72000000|libart|boot_oat|1|1|1",
        )
        assertEquals(
            0,
            ArtIntegrityDetector.vectorEFindingsFromRecords(bootOatToLibart, pkg).size,
        )
    }

    @Test
    fun `vectorEFindingsFromRecords suppresses drift WITHIN boot_oat`() {
        // Bridge moved between boot OAT segments — rare but
        // benign for declared-native methods.
        val records = arrayOf(
            "java.lang.Object#getClass|0x72005000|0x72000000|boot_oat|boot_oat|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorEFindingsFromRecords still emits drift on libart-to-jit_cache transition`() {
        // Declared-native methods do NOT legitimately route
        // through the JIT cache for their `data_` slot. A
        // libart→jit_cache transition would be Frida-Java
        // installing a bridge that happened to land in a JIT
        // page — surface it.
        val records = arrayOf(
            "java.lang.Object#hashCode|0x484b0510|0x77139d01e0|jit_cache|libart|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(
            ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_DRIFTED,
            findings[0].kind,
        )
    }

    @Test
    fun `vectorEFindingsFromRecords still emits drift on unknown-to-libart transition`() {
        // unknown snapshot can mean (a) boot.art-resident stub
        // (benign) or (b) attacker pre-poisoning. We can't tell
        // them apart at this layer, so we report and let backends
        // pivot on `snapshot_classification` / `live_classification`.
        val records = arrayOf(
            "java.lang.Object#hashCode|0x77139d01e0|0x7982f08000|libart|unknown|1|1|1",
        )
        val findings = ArtIntegrityDetector.vectorEFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        assertEquals(
            ArtIntegrityDetector.KIND_ART_METHOD_JNI_ENTRY_DRIFTED,
            findings[0].kind,
        )
    }

    // ---- Vector F — access_flags_ ACC_NATIVE bit watch tests ----

    @Test
    fun `AccessFlagsScanRecord parses a well-formed clean record`() {
        val r = ArtIntegrityDetector.AccessFlagsScanRecord.parse(
            "java.lang.String#length|0x1|0x1|1|0|0|0",
        )
        assertNotNull(r)
        r!!
        assertEquals("java.lang.String#length", r.shortId)
        assertEquals("0x1", r.liveFlagsHex)
        assertEquals("0x1", r.snapshotFlagsHex)
        assertTrue(r.readable)
        assertEquals(false, r.nativeFlippedOn)
        assertEquals(false, r.nativeFlippedOff)
        assertEquals(false, r.anyDrift)
    }

    @Test
    fun `AccessFlagsScanRecord returns null for malformed input`() {
        assertNull(ArtIntegrityDetector.AccessFlagsScanRecord.parse("not enough fields"))
        assertNull(ArtIntegrityDetector.AccessFlagsScanRecord.parse(""))
    }

    @Test
    fun `vectorFFindingsFromRecords ignores clean records`() {
        val records = arrayOf(
            "java.lang.Object#hashCode|0x100|0x100|1|0|0|0",
            "java.lang.String#length|0x1|0x1|1|0|0|0",
            // any_drift=1 but no native flip — informational only,
            // no finding (ART itself flips intrinsic markers etc).
            "java.lang.String#charAt|0x80000001|0x1|1|0|0|1",
        )
        val findings = ArtIntegrityDetector.vectorFFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorFFindingsFromRecords emits ACC_NATIVE flip-on for hooked Java method`() {
        val records = arrayOf(
            // String.length was 0x1 (public), now 0x101 (public+native)
            "java.lang.String#length|0x101|0x1|1|1|0|1",
        )
        val findings = ArtIntegrityDetector.vectorFFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        val f = findings[0]
        assertEquals(ArtIntegrityDetector.KIND_ART_METHOD_ACC_NATIVE_FLIPPED_ON, f.kind)
        assertEquals(Severity.HIGH, f.severity)
        assertEquals("java.lang.String#length", f.details["method"])
        assertEquals("0x1", f.details["snapshot_flags"])
        assertEquals("0x101", f.details["live_flags"])
    }

    @Test
    fun `vectorFFindingsFromRecords emits ACC_NATIVE flip-off for de-flagged native method`() {
        val records = arrayOf(
            // hashCode was 0x101 (public+native), now 0x1 (public only)
            "java.lang.Object#hashCode|0x1|0x101|1|0|1|1",
        )
        val findings = ArtIntegrityDetector.vectorFFindingsFromRecords(records, pkg)
        assertEquals(1, findings.size)
        val f = findings[0]
        assertEquals(ArtIntegrityDetector.KIND_ART_METHOD_ACC_NATIVE_FLIPPED_OFF, f.kind)
        assertEquals(Severity.HIGH, f.severity)
    }

    @Test
    fun `vectorFFindingsFromRecords skips unreadable slots`() {
        val records = arrayOf(
            "java.lang.System#nanoTime|0x101|0x1|0|1|0|1",
        )
        val findings = ArtIntegrityDetector.vectorFFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }

    @Test
    fun `vectorFFindingsFromRecords does not emit on benign access_flags drift`() {
        // Real-world: ART installs intrinsic markers in
        // access_flags_ during process startup, which can briefly
        // differ between JNI_OnLoad and the first scan. As long
        // as ACC_NATIVE didn't flip, we stay quiet.
        val records = arrayOf(
            "java.lang.String#length|0x80000001|0x1|1|0|0|1",
        )
        val findings = ArtIntegrityDetector.vectorFFindingsFromRecords(records, pkg)
        assertEquals(0, findings.size)
    }
}
