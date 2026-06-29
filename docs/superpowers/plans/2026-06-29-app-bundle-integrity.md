# App Bundle (AAB) Bundle-Mode Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port AAB bundle-mode integrity from DeviceIntelligenceRASP into DeviceIntelligence — baking a v3 fingerprint (decompressed dex/`.so` hashes + signer allow-set) into the `.aab`, re-signing it, and checking it at runtime across base split + splitSourceDirs via native NDK-zlib inflate.

**Architecture:** A separate plugin transform (`BundleIntegrityTask`) wires to `SingleArtifact.BUNDLE` and is mutually exclusive with the existing APK transform per variant; `AppBundleOptions.enabled` is the gate. Native decompressed hashing lives in `zip_parser.cpp` via NDK zlib and is exposed to Kotlin through a new JNI entry point `apkEntryDecompressedHash`; the runtime decision (signer membership + entry diff) stays in Kotlin inside `ApkIntegrityDetector`. Schema/codec bumped to v3 additively — existing APK blobs (v1/v2) decode unchanged.

**Tech Stack:** Kotlin + Gradle Plugin API (AGP 8.x), JDK `jdk.security.jarsigner.JarSigner` (re-sign AAB), NDK r27 C++17 + zlib (inflate in native), JUnit 5 (plugin unit tests), Android x86_64 emulator (native host C++ test via ADB).

## Global Constraints

- Schema v3 is **additive**: `MIN_SUPPORTED_FORMAT_VERSION` stays 1 in both plugin and runtime codec; v1/v2 blobs decode with `bundleMode=false`, `bundleEntryHashes=emptyMap()`.
- APK path is **byte-for-byte unchanged** when `appBundle.enabled` is false (default). All new code is guarded by the opt-in flag.
- Bundle mode is **opt-in**: `appBundle { enabled = true }`. No code runs at all for variants that don't set this.
- Entry-name normalization: `base/dex/<f>` → `<f>`; `base/lib/<abi>/<f>` → `lib/<abi>/<f>`. Both `AabHasher` (build-time) and the runtime loop use this form.
- **JAVA_HOME**: `export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2` — JDK 23 (Temurin). JDK 26 breaks Gradle 8.13.
- **Native build flags**: `-Wall -Wextra -Werror` (already in `CMakeLists.txt`).
- **Host C++ test compiler**: `$HOME/Android/Sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang++` (cross-compiles for Android x86_64; run on emulator via ADB — `clang++` is not installed on the host).
- **DI encryption divergence from RASP**: RASP uses `seed ‖ XOR(cbo, DiBaker.fpKey(seed))`; DI uses `XOR(cbo, key)` where `key` is the 32-byte `key.bin` produced by `GenerateKeyChunksTask`. `BundleFingerprintBuilder` in DI takes `key: ByteArray` directly and produces the same XOR-only envelope. No seed prefix is added.
- `fingerprint_asset_missing` remains fail-open (a `Finding`, not a crash).
- `jdk.security.jarsigner.JarSigner` is available on JDK 9+; no bundletool dependency is added.
- No `apk_entry_added` check in bundle mode (splits carry legitimate extra entries).

---

## File Map

### Created
| File | Responsibility |
|---|---|
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/AppBundleOptions.kt` | Consumer DSL: `enabled`, `playSigningCertSha256` |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/KeystoreSigning.kt` | Shared keystore-load + cert-hash helper (extracted from `InstrumentApkTask`) |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasher.kt` | Compute decompressed SHA-256 of base-module dex/`.so` entries |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabSigner.kt` | Re-sign `.aab` with JDK JarSigner |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilder.kt` | Build the v3 encrypted fingerprint blob from the `.aab` |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleIntegrityTask.kt` | AGP `BUNDLE` transform task |
| `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodecTest.kt` | v3 round-trip + v2 backward-compat codec test |
| `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasherTest.kt` | Key-normalization + decompressed-hash correctness |
| `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilderTest.kt` | Blob decodes to `bundleMode=true` + merged signer allow-set |
| `deviceintelligence/src/test/cpp/test_hash_entry_decompressed.cpp` | Native C++ host test: STORED + DEFLATED + missing + garbage |

### Modified
| File | Change |
|---|---|
| `deviceintelligence-gradle/build.gradle.kts` | Add `testImplementation(junit-jupiter)` + `useJUnitPlatform()` |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligenceExtension.kt` | Add `@Nested appBundle: AppBundleOptions` + DSL sugar |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/Fingerprint.kt` | Add `bundleMode`, `bundleEntryHashes`; bump `SCHEMA_VERSION` 2→3 |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodec.kt` | Bump `FORMAT_VERSION` 2→3; add v3 encode + decode tail |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/InstrumentApkTask.kt` | Replace inline `SigningMaterial`/`loadSigningMaterial` with `KeystoreSigning` |
| `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligencePlugin.kt` | Add bundle-mode gate + `BundleIntegrityTask` wiring; add `appBundle.enabled.convention(false)` |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/Fingerprint.kt` | Add `bundleMode`, `bundleEntryHashes`; bump `SCHEMA_VERSION` 2→3 |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/FingerprintCodec.kt` | Bump `FORMAT_VERSION` 2→3; add v3 decode branch |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/NativeBridge.kt` | Add `external fun apkEntryDecompressedHash(path: String, entryName: String): String?` |
| `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/ApkIntegrityDetector.kt` | Add bundle branch in `evaluate()` |
| `deviceintelligence/src/main/cpp/CMakeLists.txt` | Add `find_library(z-lib z)` + link zlib |
| `deviceintelligence/src/main/cpp/dicore/zip_parser.h` | Add `hash_entry_decompressed` declaration |
| `deviceintelligence/src/main/cpp/dicore/zip_parser.cpp` | Add `hash_entry_decompressed` implementation + `#include <zlib.h>` |
| `deviceintelligence/src/main/cpp/dicore/jni_bridge.cpp` | Add `apkEntryDecompressedHash` JNI function |

---

### Task 1: DSL — AppBundleOptions + DeviceIntelligenceExtension

**Files:**
- Create: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/AppBundleOptions.kt`
- Modify: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligenceExtension.kt` (lines 11–84)
- Modify: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligencePlugin.kt` (line 43 — `apply()` conventions)

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `AppBundleOptions` (abstract class) with `enabled: Property<Boolean>`, `playSigningCertSha256: SetProperty<String>`, `fun playSigningCertSha256(vararg hex: String)`. `DeviceIntelligenceExtension.appBundle: AppBundleOptions`. Both consumed by Task 4.

- [ ] **Step 1: Write the failing test**

There is no automated test for the DSL itself (Gradle property wiring is an integration concern). Instead, verify the DSL compiles and the convention is wired by building the sample. Skip ahead — the first failing test is in Task 2.

- [ ] **Step 2: Create `AppBundleOptions.kt`**

```kotlin
// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/AppBundleOptions.kt
package io.ssemaj.deviceintelligence.gradle

import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty

/**
 * Opt-in App Bundle integrity ("bundle mode").
 *
 * When [enabled], the plugin bakes a bundle-mode fingerprint (decompressed
 * dex/`.so` hashes + signer pins) into the AAB's base assets and re-signs the
 * AAB, instead of instrumenting the APK. The runtime then hashes those entries'
 * decompressed bodies across `sourceDir ∪ splitSourceDirs` and checks the
 * installed signer is a member of the baked allow-set.
 *
 * APK mode and bundle mode are mutually exclusive per variant.
 */
abstract class AppBundleOptions {
    /** Enable bundle mode for AAB builds. Default `false`. */
    abstract val enabled: Property<Boolean>

    /**
     * Play App Signing certificate SHA-256(s) to include in the signer
     * allow-set, normalized to lowercase hex with `:` separators stripped.
     * Under Play App Signing, Google re-signs delivered APKs with the app
     * signing key, so the runtime must accept that signer in addition to the
     * upload key. Empty = only the upload-key cert is in the allow-set.
     */
    abstract val playSigningCertSha256: SetProperty<String>

    /** DSL sugar: `appBundle { playSigningCertSha256("AB:CD:...") }`. */
    fun playSigningCertSha256(vararg hex: String) {
        for (h in hex) playSigningCertSha256.add(h.replace(":", "").lowercase())
    }
}
```

- [ ] **Step 3: Modify `DeviceIntelligenceExtension.kt`**

Add at the end of the class body (before the closing brace at line 84):

```kotlin
    /**
     * Opt-in App Bundle integrity ("bundle mode"). When `appBundle.enabled`
     * is `true`, the plugin bakes a bundle-mode fingerprint into the AAB and
     * re-signs it instead of instrumenting the APK.
     */
    @get:org.gradle.api.tasks.Nested
    abstract val appBundle: AppBundleOptions

    /** DSL sugar: `deviceIntelligence { appBundle { enabled = true } }`. */
    fun appBundle(action: org.gradle.api.Action<AppBundleOptions>) = action.execute(appBundle)
```

- [ ] **Step 4: Wire the `appBundle.enabled` convention in `DeviceIntelligencePlugin.apply()`**

In `DeviceIntelligencePlugin.kt`, the `apply()` method creates the extension at line 37. After `disableAutoRuntimeDependency.convention(false)` (currently the last convention, line 43), add:

```kotlin
            appBundle.enabled.convention(false)
            appBundle.playSigningCertSha256.convention(emptySet())
```

- [ ] **Step 5: Verify compilation**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
cd /home/joseph/AndroidStudioProjects/DeviceIntelligence
./gradlew :deviceintelligence-gradle:compileKotlin
```

Expected: BUILD SUCCESSFUL. Fix any compile errors before continuing.

- [ ] **Step 6: Commit**

```bash
git add deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/AppBundleOptions.kt \
        deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligenceExtension.kt \
        deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligencePlugin.kt
git commit -m "feat(bundle): add AppBundleOptions DSL + extension wire"
```

---

### Task 2: Fingerprint v3 + Codec v3 (plugin + runtime) + codec unit tests

**Files:**
- Modify: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/Fingerprint.kt` (line 63: SCHEMA_VERSION=2)
- Modify: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodec.kt` (line 66: FORMAT_VERSION=2)
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/Fingerprint.kt` (line 60: SCHEMA_VERSION=2)
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/FingerprintCodec.kt` (line 43: FORMAT_VERSION=2)
- Modify: `deviceintelligence-gradle/build.gradle.kts` (add test deps + JUnit platform)
- Create: `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodecTest.kt`

**Interfaces:**
- Consumes: nothing new (extends existing types)
- Produces:
  - Plugin `Fingerprint(bundleMode: Boolean = false, bundleEntryHashes: Map<String,String> = emptyMap())` (new default fields)
  - Plugin `FingerprintCodec.FORMAT_VERSION = 3`, `encode()` writes v3 tail, `decode()` reads v3 tail when `formatVersion >= 3`
  - Runtime `Fingerprint.bundleMode: Boolean`, `Fingerprint.bundleEntryHashes: Map<String,String>` (same defaults)
  - Runtime `FingerprintCodec.FORMAT_VERSION = 3` (accepts 1..3, reads v3 tail)
  - All consumed by Tasks 3, 4, 6.

- [ ] **Step 1: Set up test infrastructure in `build.gradle.kts`**

In `deviceintelligence-gradle/build.gradle.kts`, add the test dependency and JUnit platform configuration. After the existing `dependencies {}` block:

```kotlin
dependencies {
    // (existing entries unchanged)
    compileOnly("com.android.tools.build:gradle-api:8.13.2")
    implementation("com.android.tools.build:apksig:8.13.2")

    // JUnit 5 for plugin unit tests
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
```

Create the test source directory:
```bash
mkdir -p /home/joseph/AndroidStudioProjects/DeviceIntelligence/deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal
```

- [ ] **Step 2: Write the failing codec test**

Create `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodecTest.kt`:

```kotlin
package io.ssemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class FingerprintCodecTest {

    /** A v3 bundle-mode fingerprint round-trips through encode → decode. */
    @Test fun bundleModeRoundTrip() {
        val fp = baseFingerprint().copy(
            bundleMode = true,
            bundleEntryHashes = mapOf(
                "classes.dex" to "aabbccddeeff0011",
                "lib/arm64-v8a/libdicore.so" to "00112233445566778899",
            ),
        )
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))

        assertEquals(true, back.bundleMode)
        assertEquals(fp.bundleEntryHashes, back.bundleEntryHashes)
        assertEquals(3, FingerprintCodec.FORMAT_VERSION)
    }

    /** A v3 APK-mode fingerprint (bundleMode=false) also round-trips. */
    @Test fun apkModeRoundTripStillWorks() {
        val fp = baseFingerprint() // bundleMode=false by default
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))

        assertEquals(false, back.bundleMode)
        assertEquals(emptyMap<String, String>(), back.bundleEntryHashes)
        assertEquals("release", back.variantName)
    }

    /** bundleEntryHashes keys are sorted on encode; order is stable. */
    @Test fun bundleEntryHashesSortedOnEncode() {
        val fp = baseFingerprint().copy(
            bundleMode = true,
            bundleEntryHashes = mapOf(
                "lib/arm64-v8a/libfoo.so" to "cc",
                "classes.dex" to "aa",
                "classes2.dex" to "bb",
            ),
        )
        val bytes = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        val back = FingerprintCodec.decode(ByteArrayInputStream(bytes))

        // Sorted order: classes.dex, classes2.dex, lib/arm64-v8a/libfoo.so
        val keys = back.bundleEntryHashes.keys.toList()
        assertEquals(listOf("classes.dex", "classes2.dex", "lib/arm64-v8a/libfoo.so"), keys)
    }

    private fun baseFingerprint() = Fingerprint(
        schemaVersion = Fingerprint.SCHEMA_VERSION,
        builtAtEpochMs = 1_000_000L,
        pluginVersion = "5.0.0",
        variantName = "release",
        applicationId = "io.ssemaj.sample",
        signerCertSha256 = listOf("deadbeef01234567"),
        entries = mapOf("classes.dex" to "hash0"),
        ignoredEntries = listOf("assets/io.ssemaj.deviceintelligence/fingerprint.bin"),
        ignoredEntryPrefixes = listOf("META-INF/"),
        expectedSourceDirPrefix = "/data/app/",
        expectedInstallerWhitelist = emptyList(),
        nativeLibInventoryByAbi = mapOf("arm64-v8a" to listOf("libdicore.so")),
        dicoreTextSha256ByAbi = mapOf("arm64-v8a" to "texthash"),
    )
}
```

- [ ] **Step 3: Run the test to verify it fails (missing fields)**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
cd /home/joseph/AndroidStudioProjects/DeviceIntelligence
./gradlew :deviceintelligence-gradle:test --tests "*.FingerprintCodecTest" 2>&1 | tail -30
```

Expected: FAILED — compilation error because `Fingerprint` has no `bundleMode`/`bundleEntryHashes` field and `FORMAT_VERSION` is 2.

- [ ] **Step 4: Modify plugin `Fingerprint.kt` — add v3 fields + bump SCHEMA_VERSION**

In `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/Fingerprint.kt`:

After `val dicoreTextSha256ByAbi: Map<String, String> = emptyMap(),` (line 54), add:

```kotlin
    /** v3 — true when baked for an App Bundle build (split-aware, decompressed hashing). */
    val bundleMode: Boolean = false,
    /**
     * v3 — APK-relative entry path -> SHA-256 hex of the entry's DECOMPRESSED body,
     * for `classes*.dex` + `.so` files under `lib/<abi>/`. Used only in bundle mode;
     * `entries` is left empty in bundle mode because Play re-deflates, making
     * compressed-byte hashes unstable.
     */
    val bundleEntryHashes: Map<String, String> = emptyMap(),
```

Change `const val SCHEMA_VERSION: Int = 2` to `const val SCHEMA_VERSION: Int = 3`.

Update the KDoc comment for SCHEMA_VERSION:
```kotlin
        /**
         * Bumped from 1 to 2 to add `nativeLibInventoryByAbi`, `nativeLibHashesByAbi`,
         * and `dicoreTextSha256ByAbi`.
         * Bumped from 2 to 3 to add `bundleMode` and `bundleEntryHashes` for App Bundle
         * integrity support. Runtime decoder accepts v1/v2/v3; older blobs leave the new
         * fields at their defaults (bundleMode=false, bundleEntryHashes=emptyMap()).
         */
        const val SCHEMA_VERSION: Int = 3
```

- [ ] **Step 5: Modify plugin `FingerprintCodec.kt` — bump FORMAT_VERSION, add v3 encode + decode**

Change `const val FORMAT_VERSION: Int = 2` to `const val FORMAT_VERSION: Int = 3`.

In `encode()`, after the v2 tail block (after the closing brace of the `textAbis` loop, just before `flush()`), add:

```kotlin
            // v3 tail — sorted by entry name for byte-deterministic output.
            writeBoolean(fp.bundleMode)
            val bundleKeys = fp.bundleEntryHashes.keys.sorted()
            writeInt(bundleKeys.size)
            for (k in bundleKeys) {
                writeUTF(k)
                writeUTF(fp.bundleEntryHashes.getValue(k))
            }
```

In `decode()`, declare the v3 variables alongside the v2 variables. Find the block starting `var inventoryByAbi: Map<String, List<String>> = emptyMap()` (line 190) and add two more lines after `var textHashByAbi: Map<String, String> = emptyMap()`:

```kotlin
            var bundleMode = false
            var bundleEntryHashes: Map<String, String> = emptyMap()
```

After the `if (formatVersion >= 2) { ... }` block (after its closing brace, before `return Fingerprint(`), add:

```kotlin
            // v3 tail — absent on v1/v2 blobs; fields stay at their defaults.
            if (formatVersion >= 3) {
                bundleMode = readBoolean()
                val bundleCount = readInt()
                bundleEntryHashes = LinkedHashMap<String, String>(bundleCount).apply {
                    repeat(bundleCount) {
                        val name = readUTF()
                        val sha = readUTF()
                        put(name, sha)
                    }
                }
            }
```

In the `return Fingerprint(...)` call, add the two new fields (after `dicoreTextSha256ByAbi = textHashByAbi,`):

```kotlin
                bundleMode = bundleMode,
                bundleEntryHashes = bundleEntryHashes,
```

Also update the wire-format comment at the top of `FingerprintCodec.kt` to append:
```
 *   --- v3 additions below ---
 *   uint8   bundleMode             (0/1)
 *   uint32  bundleEntryCount
 *     utf8  entryName    [bundleEntryCount times, sorted]
 *     utf8  sha256Hex    [bundleEntryCount times]
```

- [ ] **Step 6: Run the test to verify it passes**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :deviceintelligence-gradle:test --tests "*.FingerprintCodecTest" 2>&1 | tail -20
```

Expected: 3 tests, BUILD SUCCESSFUL.

- [ ] **Step 7: Modify runtime `Fingerprint.kt` — add v3 fields + bump SCHEMA_VERSION**

In `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/Fingerprint.kt`:

After `val dicoreTextSha256ByAbi: Map<String, String> = emptyMap(),` (line 56), add:

```kotlin
    /** v3 — true when baked for an App Bundle build (split-aware, decompressed hashing). */
    val bundleMode: Boolean = false,
    /**
     * v3 — APK-relative entry path -> SHA-256 hex of the entry's DECOMPRESSED body,
     * for `classes*.dex` + `.so` files under `lib/<abi>/`. Used only in bundle mode.
     */
    val bundleEntryHashes: Map<String, String> = emptyMap(),
```

Change `const val SCHEMA_VERSION: Int = 2` to `const val SCHEMA_VERSION: Int = 3`.

- [ ] **Step 8: Modify runtime `FingerprintCodec.kt` — bump FORMAT_VERSION, add v3 decode**

Change `const val FORMAT_VERSION: Int = 2` to `const val FORMAT_VERSION: Int = 3`.

Declare v3 variables alongside the v2 variables. Find the block starting `var inventoryByAbi:` (line 109) and add after `var textHashByAbi: Map<String, String> = emptyMap()`:

```kotlin
        var bundleMode = false
        var bundleEntryHashes: Map<String, String> = emptyMap()
```

After the `if (formatVersion >= 2) { ... }` block's closing brace (line 149), add:

```kotlin
        if (formatVersion >= 3) {
            bundleMode = din.readBoolean()
            val bundleCount = readNonNegative(din.readInt(), "bundleEntryCount")
            bundleEntryHashes = LinkedHashMap<String, String>(bundleCount).apply {
                repeat(bundleCount) {
                    val name = din.readUTF()
                    val sha = din.readUTF()
                    put(name, sha)
                }
            }
        }
```

In the `return Fingerprint(...)` call, add (after `dicoreTextSha256ByAbi = textHashByAbi,`):

```kotlin
            bundleMode = bundleMode,
            bundleEntryHashes = bundleEntryHashes,
```

Also update `FORMAT_VERSION` range in the decode require (it becomes `1..3` automatically because `FORMAT_VERSION` is now 3).

Update the wire-format comment at the top to include the v3 tail entries.

- [ ] **Step 9: Verify runtime module compiles**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :deviceintelligence:compileReleaseKotlin 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 10: Commit**

```bash
git add \
    deviceintelligence-gradle/build.gradle.kts \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/Fingerprint.kt \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodec.kt \
    deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/FingerprintCodecTest.kt \
    deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/Fingerprint.kt \
    deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/FingerprintCodec.kt
git commit -m "feat(bundle): bump schema+codec to v3 — bundleMode + bundleEntryHashes"
```

---

### Task 3: KeystoreSigning + AabHasher + AabSigner + BundleFingerprintBuilder

**Files:**
- Create: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/KeystoreSigning.kt`
- Create: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasher.kt`
- Create: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabSigner.kt`
- Create: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilder.kt`
- Modify: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/InstrumentApkTask.kt` (replace inline `SigningMaterial` + `loadSigningMaterial()` with `KeystoreSigning`)
- Create: `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasherTest.kt`
- Create: `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilderTest.kt`

**Interfaces:**
- Consumes: `Fingerprint` v3, `FingerprintCodec` v3, `NativeLibInventory.walkRawEntries()` (unchanged).
- Produces:
  - `KeystoreSigning.load(keystoreFile, configuredType, keystorePassword, alias, entryPassword): KeystoreSigning.Material` where `Material(privateKey: PrivateKey, certs: List<X509Certificate>, certHashes: List<String>)`
  - `AabHasher.bundleEntryHashes(aab: File): Map<String, String>` — keyed by normalized installed-APK entry name
  - `AabSigner.sign(aab: File, key: PrivateKey, certs: List<X509Certificate>)`
  - `BundleFingerprintBuilder.build(aab: File, key: ByteArray, signerCertHashes: List<String>, playPins: Collection<String>, pluginVersion: String, variant: String, appId: String): ByteArray`
  - All consumed by Task 4 (`BundleIntegrityTask`).

- [ ] **Step 1: Write the failing `AabHasherTest`**

Create `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasherTest.kt`:

```kotlin
package io.ssemaj.deviceintelligence.gradle.internal

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AabHasherTest {

    @Test fun normalizesPathsAndHashesDecompressedBytes(@TempDir dir: File) {
        val dex = "DEXBYTES_UNIQUE_CONTENT_12345".toByteArray()
        val so  = "SOBYTES_UNIQUE_CONTENT_67890".toByteArray()
        val aab = File(dir, "app.aab")

        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/dex/classes.dex")); z.write(dex); z.closeEntry()
            z.putNextEntry(ZipEntry("base/dex/classes2.dex")); z.write("C2".toByteArray()); z.closeEntry()
            z.putNextEntry(ZipEntry("base/lib/arm64-v8a/libdicore.so")); z.write(so); z.closeEntry()
            // These must be excluded:
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("RESOURCES".toByteArray()); z.closeEntry()
            z.putNextEntry(ZipEntry("base/manifest/AndroidManifest.xml")); z.write("XML".toByteArray()); z.closeEntry()
        }

        val result = AabHasher.bundleEntryHashes(aab)

        // Entry names use installed-APK keys, not bundle keys.
        assertEquals(
            setOf("classes.dex", "classes2.dex", "lib/arm64-v8a/libdicore.so"),
            result.keys,
        )
        // Hash is the decompressed (inflated) SHA-256.
        assertEquals(sha256Hex(dex), result["classes.dex"])
        assertEquals(sha256Hex(so),  result["lib/arm64-v8a/libdicore.so"])
        // Resources and manifest are excluded.
        assertFalse("base/resources.pb" in result.keys)
        assertFalse("resources.pb" in result.keys)
    }

    @Test fun emptyAabProducesEmptyMap(@TempDir dir: File) {
        val aab = File(dir, "empty.aab")
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("R".toByteArray()); z.closeEntry()
        }
        assertEquals(emptyMap<String, String>(), AabHasher.bundleEntryHashes(aab))
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}
```

- [ ] **Step 2: Run to confirm FAIL**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :deviceintelligence-gradle:test --tests "*.AabHasherTest" 2>&1 | tail -20
```

Expected: FAILED — `AabHasher` not found.

- [ ] **Step 3: Create `KeystoreSigning.kt`**

```kotlin
// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/KeystoreSigning.kt
package io.ssemaj.deviceintelligence.gradle.internal

import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * Shared keystore-load helper shared between [InstrumentApkTask] and
 * [BundleIntegrityTask]. Extracted here so both tasks load signing material
 * identically without duplicating the PKCS12 / JKS fallback logic.
 */
internal object KeystoreSigning {

    data class Material(
        val privateKey: PrivateKey,
        val certs: List<X509Certificate>,
        val certHashes: List<String>,
    )

    /**
     * Load [Material] from [keystoreFile]. Tries [configuredType] first (if non-null),
     * then PKCS12, then JKS. Throws [IllegalStateException] if none succeeds.
     */
    fun load(
        keystoreFile: File,
        configuredType: String?,
        keystorePassword: String,
        alias: String,
        entryPassword: String?,
    ): Material {
        require(keystoreFile.isFile) { "keystore not found: $keystoreFile" }

        val candidates = buildList {
            if (!configuredType.isNullOrEmpty()) add(configuredType.uppercase())
            add("PKCS12")
            add("JKS")
        }.distinct()

        var ks: KeyStore? = null
        var lastError: Throwable? = null
        for (type in candidates) {
            try {
                val candidate = KeyStore.getInstance(type)
                FileInputStream(keystoreFile).use { candidate.load(it, keystorePassword.toCharArray()) }
                ks = candidate
                break
            } catch (e: Throwable) {
                lastError = e
            }
        }
        ks ?: throw IllegalStateException(
            "Failed to load keystore $keystoreFile as any of $candidates",
            lastError,
        )

        val pwd = (entryPassword ?: keystorePassword).toCharArray()
        val privateKey = ks.getKey(alias, pwd) as? PrivateKey
            ?: error("alias '$alias' has no PrivateKey entry in $keystoreFile")
        val rawChain = ks.getCertificateChain(alias)
            ?: ks.getCertificate(alias)?.let { arrayOf(it) }
            ?: error("alias '$alias' has no certificate in $keystoreFile")
        val certs = rawChain.map {
            require(it is X509Certificate) { "non-X.509 cert in chain: ${it::class}" }
            it
        }
        val md = MessageDigest.getInstance("SHA-256")
        val certHashes = certs.map { cert ->
            md.reset()
            md.digest(cert.encoded).joinToString("") { b -> "%02x".format(b) }
        }
        return Material(privateKey, certs, certHashes)
    }
}
```

- [ ] **Step 4: Refactor `InstrumentApkTask.kt` to use `KeystoreSigning`**

In `InstrumentApkTask.kt`:

Remove the private `data class SigningMaterial(...)` (lines 431–435) and the private `fun loadSigningMaterial(...)` (lines 437–488).

Change the call site at line 149:
```kotlin
        val signing = loadSigningMaterial(
            keystoreFile = keystoreFile.get().asFile,
            configuredType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
            entryPassword = keyPassword.orNull,
        )
```
to:
```kotlin
        val signing = KeystoreSigning.load(
            keystoreFile = keystoreFile.get().asFile,
            configuredType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
            entryPassword = keyPassword.orNull,
        )
```

Replace all remaining uses of `signing.privateKey`, `signing.certs`, `signing.certHashes` — these names are the same in `KeystoreSigning.Material`, so no further changes are needed.

Remove the `import` for `FileInputStream` if it's no longer used directly in `InstrumentApkTask` (check remaining usages first).

- [ ] **Step 5: Create `AabHasher.kt`**

```kotlin
// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasher.kt
package io.ssemaj.deviceintelligence.gradle.internal

import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Reads an Android App Bundle (`.aab`) and returns the SHA-256 of the
 * DECOMPRESSED body of every `classes*.dex` and `.so` entry under `lib/<abi>/`
 * in the base module, keyed by the APK-relative path the runtime sees on-device:
 *
 *   `base/dex/classes.dex`             → `classes.dex`
 *   `base/lib/arm64-v8a/libdicore.so`  → `lib/arm64-v8a/libdicore.so`
 *
 * We hash the decompressed bytes (not the compressed body, as APK mode does)
 * because Play re-encodes split APKs during delivery — only the inflated
 * payload is stable between build time and the installed device.
 *
 * Resources and the manifest are intentionally excluded: they are covered
 * transitively by the signer pin, and Play rewrites `resources.pb` to binary
 * `resources.arsc` so a byte hash would never match.
 */
internal object AabHasher {

    fun bundleEntryHashes(aab: File): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        ZipFile(aab).use { zf ->
            val entries = zf.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                if (e.isDirectory) continue
                val apkPath = when {
                    e.name.startsWith("base/dex/") && e.name.endsWith(".dex") ->
                        e.name.removePrefix("base/dex/")          // classes.dex
                    e.name.startsWith("base/lib/") && e.name.endsWith(".so") ->
                        e.name.removePrefix("base/")              // lib/<abi>/<file>.so
                    else -> null
                } ?: continue

                val md = MessageDigest.getInstance("SHA-256")
                // ZipFile.getInputStream yields the DECOMPRESSED bytes regardless of
                // the entry's compression method — this is what we want.
                zf.getInputStream(e).use { ins ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = ins.read(buf)
                        if (n < 0) break
                        md.update(buf, 0, n)
                    }
                }
                out[apkPath] = md.digest().joinToString("") { b -> "%02x".format(b) }
            }
        }
        return out
    }
}
```

- [ ] **Step 6: Create `AabSigner.kt`**

```kotlin
// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabSigner.kt
package io.ssemaj.deviceintelligence.gradle.internal

import jdk.security.jarsigner.JarSigner
import java.io.File
import java.io.FileOutputStream
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * JAR-signs (v1 / "JAR signing") a modified `.aab` so `bundletool validate`
 * and Play accept it after the plugin injects the bundle-mode fingerprint asset.
 *
 * Uses the JDK's in-process [JarSigner] (module `jdk.jartool`). The input
 * `.aab` must contain ONLY file entries — bundletool rejects directory entries.
 * [BundleIntegrityTask] is responsible for emitting a clean repack;
 * this signer copies entries through verbatim.
 *
 * Single-signer only (matching [InstrumentApkTask]).
 */
internal object AabSigner {

    fun sign(aab: File, key: PrivateKey, certs: List<X509Certificate>) {
        require(certs.isNotEmpty()) { "no signer certificates supplied for $aab" }
        val certPath = CertificateFactory.getInstance("X.509").generateCertPath(certs)
        val signer = JarSigner.Builder(key, certPath)
            .digestAlgorithm("SHA-256")
            .signerName("DI")
            .build()

        // JarSigner requires distinct input/output streams. Sign to a temp
        // sibling then atomically replace the original.
        val signed = File(aab.parentFile, "${aab.name}.signed")
        ZipFile(aab).use { zf ->
            FileOutputStream(signed).use { out -> signer.sign(zf, out) }
        }
        if (!signed.renameTo(aab)) {
            signed.copyTo(aab, overwrite = true)
            signed.delete()
        }
    }
}
```

- [ ] **Step 7: Create `BundleFingerprintBuilder.kt`**

**DI-specific adaptation:** RASP's `BundleFingerprintBuilder` calls `DiBaker.fpKey(seed)` and produces a `seed ‖ XOR(cbo, fpKey(seed))` envelope. DI has no `DiBaker`; it uses the pre-shared `key.bin` from `GenerateKeyChunksTask`. The builder here takes `key: ByteArray` directly and produces `XOR(cbo, key)` — the same format `FingerprintDecoder.decode()` already decrypts at runtime.

```kotlin
// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilder.kt
package io.ssemaj.deviceintelligence.gradle.tasks

import io.ssemaj.deviceintelligence.gradle.internal.AabHasher
import io.ssemaj.deviceintelligence.gradle.internal.Fingerprint
import io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec
import io.ssemaj.deviceintelligence.gradle.internal.NativeLibInventory
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipFile

/**
 * Pure builder for the bundle-mode fingerprint blob baked into an AAB's base
 * assets. Kept free of AGP/Gradle types so it can be unit-tested directly.
 *
 * Encryption: `XOR(encode(fp), key)` — the same scheme APK mode uses
 * ([InstrumentApkTask] reads `key.bin` from [GenerateKeyChunksTask] and XORs).
 * At runtime [KeyResolver.assembleKey] returns the same key; [FingerprintDecoder]
 * XOR-decrypts and passes to [FingerprintCodec.decode].
 *
 * DI divergence from RASP: RASP uses `DiBaker.fpKey(seed)` producing a
 * `seed ‖ ciphertext` envelope. DI has no DiBaker — the caller passes `key`
 * (the 32-byte `key.bin`) and the output is simply `XOR(cbo, key)`.
 */
internal object BundleFingerprintBuilder {

    /**
     * Build the encrypted bundle-mode fingerprint blob for [aab].
     *
     * @param aab The `.aab` file (AGP-built, before injection).
     * @param key The 32-byte per-build XOR key from `GenerateKeyChunksTask.keyFile`.
     * @param signerCertHashes SHA-256 hex hashes of the upload-key cert(s).
     * @param playPins Play App Signing cert SHA-256(s) declared in `appBundle.playSigningCertSha256`.
     * @param pluginVersion Plugin version string baked into the fingerprint.
     * @param variant AGP variant name (e.g. `"release"`).
     * @param appId Application ID.
     * @return `XOR(FingerprintCodec.encode(fp), key)` as a byte array.
     */
    fun build(
        aab: File,
        key: ByteArray,
        signerCertHashes: List<String>,
        playPins: Collection<String>,
        pluginVersion: String,
        variant: String,
        appId: String,
    ): ByteArray {
        val bundleEntries = AabHasher.bundleEntryHashes(aab)
        val nativeFp = NativeLibInventory.walkRawEntries(aabBaseLibEntries(aab))

        // Membership allow-set: upload-key cert(s) ∪ Play App Signing pins, de-duped.
        val signerAllowSet = (signerCertHashes + playPins).distinct()

        val fp = Fingerprint(
            schemaVersion = Fingerprint.SCHEMA_VERSION,
            builtAtEpochMs = System.currentTimeMillis(),
            pluginVersion = pluginVersion,
            variantName = variant,
            applicationId = appId,
            signerCertSha256 = signerAllowSet,
            // Bundle mode does not bake compressed-byte entry hashes — Play re-deflates.
            entries = emptyMap(),
            ignoredEntries = emptyList(),
            ignoredEntryPrefixes = emptyList(),
            expectedSourceDirPrefix = "/data/app/",
            expectedInstallerWhitelist = emptyList(),
            nativeLibInventoryByAbi = nativeFp.inventoryByAbi,
            nativeLibHashesByAbi = nativeFp.fileHashesByAbi,
            dicoreTextSha256ByAbi = nativeFp.dicoreTextSha256ByAbi,
            bundleMode = true,
            bundleEntryHashes = bundleEntries,
        )

        val cbo = ByteArrayOutputStream().apply { FingerprintCodec.encode(fp, this) }.toByteArray()
        return ByteArray(cbo.size).also { out ->
            for (i in cbo.indices) {
                out[i] = (cbo[i].toInt() xor key[i % key.size].toInt()).toByte()
            }
        }
    }

    /**
     * Stream the AAB's `base/lib/<abi>/<file>.so` entries as
     * `lib/<abi>/<file>.so` (APK-relative) path + decompressed body pairs,
     * so [NativeLibInventory.walkRawEntries] computes the ELF `.text`
     * baseline identically to APK mode.
     */
    private fun aabBaseLibEntries(aab: File): Sequence<Pair<String, ByteArray>> {
        val list = ArrayList<Pair<String, ByteArray>>()
        ZipFile(aab).use { zf ->
            val it = zf.entries()
            while (it.hasMoreElements()) {
                val e = it.nextElement()
                if (e.isDirectory) continue
                if (!e.name.startsWith("base/lib/") || !e.name.endsWith(".so")) continue
                val apkPath = e.name.removePrefix("base/") // lib/<abi>/<file>.so
                val bytes = zf.getInputStream(e).use { s -> s.readBytes() }
                list += apkPath to bytes
            }
        }
        return list.asSequence()
    }
}
```

- [ ] **Step 8: Write `BundleFingerprintBuilderTest`**

Create `deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilderTest.kt`.

First, create the directory:
```bash
mkdir -p /home/joseph/AndroidStudioProjects/DeviceIntelligence/deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/tasks
```

```kotlin
package io.ssemaj.deviceintelligence.gradle.tasks

import io.ssemaj.deviceintelligence.gradle.internal.FingerprintCodec
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class BundleFingerprintBuilderTest {

    @Test fun blobDecodesToBundleModeWithMergedSigners(@TempDir dir: File) {
        val dex = "DEXBYTES".toByteArray()
        val so  = "SOBYTES".toByteArray()
        val aab = File(dir, "app.aab")
        ZipOutputStream(aab.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("base/dex/classes.dex")); z.write(dex); z.closeEntry()
            z.putNextEntry(ZipEntry("base/lib/arm64-v8a/libother.so")); z.write(so); z.closeEntry()
            z.putNextEntry(ZipEntry("base/resources.pb")); z.write("R".toByteArray()); z.closeEntry()
        }

        val key = ByteArray(32) { it.toByte() } // deterministic test key

        val blob = BundleFingerprintBuilder.build(
            aab = aab,
            key = key,
            signerCertHashes = listOf("aa11"),
            playPins = listOf("bb22", "aa11"), // overlap must be de-duplicated
            pluginVersion = "5.0.0",
            variant = "release",
            appId = "io.ssemaj.sample",
        )

        // Decrypt: XOR with the same key.
        val plain = ByteArray(blob.size) { i -> (blob[i].toInt() xor key[i % 32].toInt()).toByte() }
        val fp = FingerprintCodec.decode(ByteArrayInputStream(plain))

        assertTrue(fp.bundleMode)
        assertEquals(sha256Hex(dex), fp.bundleEntryHashes["classes.dex"])
        assertEquals(sha256Hex(so),  fp.bundleEntryHashes["lib/arm64-v8a/libother.so"])
        assertFalse("base/resources.pb" in fp.bundleEntryHashes.keys)
        // De-duplicated merged signer allow-set.
        assertEquals(setOf("aa11", "bb22"), fp.signerCertSha256.toSet())
        assertEquals("io.ssemaj.sample", fp.applicationId)
        // APK-mode entries is empty in bundle mode.
        assertTrue(fp.entries.isEmpty())
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
}
```

- [ ] **Step 9: Run all plugin tests**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :deviceintelligence-gradle:test 2>&1 | tail -30
```

Expected: all tests pass (`FingerprintCodecTest` × 3, `AabHasherTest` × 2, `BundleFingerprintBuilderTest` × 1). BUILD SUCCESSFUL.

- [ ] **Step 10: Commit**

```bash
git add \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/KeystoreSigning.kt \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasher.kt \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabSigner.kt \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilder.kt \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/InstrumentApkTask.kt \
    deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/internal/AabHasherTest.kt \
    deviceintelligence-gradle/src/test/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleFingerprintBuilderTest.kt
git commit -m "feat(bundle): KeystoreSigning, AabHasher, AabSigner, BundleFingerprintBuilder"
```

---

### Task 4: BundleIntegrityTask + Plugin Gate

**Files:**
- Create: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleIntegrityTask.kt`
- Modify: `deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligencePlugin.kt`

**Interfaces:**
- Consumes: `BundleFingerprintBuilder.build(...)`, `AabSigner.sign(...)`, `KeystoreSigning.load(...)`, `GenerateKeyChunksTask.keyFile`, `AppBundleOptions.enabled`, `AppBundleOptions.playSigningCertSha256`.
- Produces: wired `SingleArtifact.BUNDLE` transform on the consumer's AAB. The APK transform (`InstrumentApkTask`) is skipped entirely for variants where `bundleMode=true`.

- [ ] **Step 1: Create `BundleIntegrityTask.kt`**

```kotlin
// deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleIntegrityTask.kt
package io.ssemaj.deviceintelligence.gradle.tasks

import io.ssemaj.deviceintelligence.gradle.internal.AabSigner
import io.ssemaj.deviceintelligence.gradle.internal.Fingerprint
import io.ssemaj.deviceintelligence.gradle.internal.KeystoreSigning
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.SetProperty
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/**
 * App Bundle ("bundle mode") integrity transform over [SingleArtifact.BUNDLE].
 *
 * AGP hands us the just-built, AGP-signed `.aab`; we:
 *   1. Bake the v3 bundle-mode fingerprint blob (decompressed dex/`.so` hashes +
 *      signer allow-set) with [BundleFingerprintBuilder].
 *   2. Repack the AAB with `base/assets/io.ssemaj.deviceintelligence/fingerprint.bin`
 *      injected as a STORED entry, stripping the old `META-INF/` signature and any
 *      pre-existing fingerprint. ONLY file entries are emitted — bundletool rejects
 *      directory entries in a re-packed AAB.
 *   3. JAR-re-sign the result with [AabSigner].
 *
 * Encryption: `XOR(encode(fp), key)` using the per-build `key.bin` from
 * [GenerateKeyChunksTask]. At runtime [FingerprintDecoder] decrypts with the
 * same key recovered via [KeyResolver.assembleKey].
 */
abstract class BundleIntegrityTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val inputAab: RegularFileProperty

    @get:OutputFile
    abstract val outputAab: RegularFileProperty

    /** Per-build XOR key from [GenerateKeyChunksTask]. */
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val keyFile: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val keystoreFile: RegularFileProperty

    @get:Input
    @get:Optional
    abstract val keystoreType: Property<String>

    @get:Input
    abstract val keystorePassword: Property<String>

    @get:Input
    abstract val keyAlias: Property<String>

    @get:Input
    @get:Optional
    abstract val keyPassword: Property<String>

    /** Play App Signing cert SHA-256 pins to include in the signer allow-set. */
    @get:Input
    abstract val playSigningCertSha256: SetProperty<String>

    @get:Input
    abstract val variantName: Property<String>

    @get:Input
    abstract val applicationId: Property<String>

    @get:Input
    abstract val pluginVersion: Property<String>

    @TaskAction
    fun run() {
        val key = keyFile.get().asFile.readBytes()
        require(key.size == KEY_SIZE) {
            "key.bin is wrong size: ${key.size}B (expected $KEY_SIZE)"
        }

        val signing = KeystoreSigning.load(
            keystoreFile = keystoreFile.get().asFile,
            configuredType = keystoreType.orNull,
            keystorePassword = keystorePassword.get(),
            alias = keyAlias.get(),
            entryPassword = keyPassword.orNull,
        )

        val input = inputAab.get().asFile
        val output = outputAab.get().asFile.apply { parentFile?.mkdirs() }

        val blob = BundleFingerprintBuilder.build(
            aab = input,
            key = key,
            signerCertHashes = signing.certHashes,
            playPins = playSigningCertSha256.getOrElse(emptySet()),
            pluginVersion = pluginVersion.get(),
            variant = variantName.get(),
            appId = applicationId.get(),
        )
        logger.lifecycle(
            "io.ssemaj: bundle-mode fingerprint '${variantName.get()}': " +
                "signerLeaf=${signing.certHashes.firstOrNull()}, " +
                "playPins=${playSigningCertSha256.getOrElse(emptySet()).size}, " +
                "bundleEntries=${blob.size}B"
        )

        injectAsset(input, output, BUNDLE_ASSET_PATH to blob)
        AabSigner.sign(output, signing.privateKey, signing.certs)

        logger.lifecycle(
            "io.ssemaj: bundle-mode integrity → ${output.relativeTo(project.rootDir)} (asset injected, re-signed)"
        )
    }

    /**
     * Copies every file entry from [input] to [output], DROPPING `META-INF/`
     * (old signature), any pre-existing fingerprint asset, and all directory
     * entries (bundletool rejects them in a re-packed AAB); then appends
     * [additional] as a STORED entry.
     */
    private fun injectAsset(input: File, output: File, additional: Pair<String, ByteArray>) {
        if (output.exists()) output.delete()
        ZipFile(input).use { zf ->
            ZipOutputStream(output.outputStream().buffered()).use { zos ->
                val it = zf.entries()
                while (it.hasMoreElements()) {
                    val e = it.nextElement()
                    if (e.isDirectory) continue
                    if (e.name.startsWith("META-INF/")) continue
                    if (e.name == additional.first) continue
                    val bytes = zf.getInputStream(e).use { s -> s.readBytes() }
                    val method = if (e.method == ZipEntry.STORED) ZipEntry.STORED else ZipEntry.DEFLATED
                    writeEntry(zos, e.name, bytes, method, e.time)
                }
                writeEntry(zos, additional.first, additional.second, ZipEntry.STORED, 0L)
            }
        }
    }

    private fun writeEntry(zos: ZipOutputStream, name: String, data: ByteArray, method: Int, time: Long) {
        val entry = ZipEntry(name).apply {
            this.method = method
            this.time = time
            if (method == ZipEntry.STORED) {
                size = data.size.toLong()
                compressedSize = data.size.toLong()
                crc = CRC32().apply { update(data) }.value
            }
        }
        zos.putNextEntry(entry)
        zos.write(data)
        zos.closeEntry()
    }

    private companion object {
        /** Fingerprint asset path inside the AAB's base module. */
        val BUNDLE_ASSET_PATH: String = "base/" + Fingerprint.ASSET_PATH
        const val KEY_SIZE: Int = 32
    }
}
```

- [ ] **Step 2: Wire `BundleIntegrityTask` in `DeviceIntelligencePlugin.kt`**

In `DeviceIntelligencePlugin.kt`, add an import at the top:

```kotlin
import io.ssemaj.deviceintelligence.gradle.tasks.BundleIntegrityTask
```

Inside `wireApplication()`, after the signing-material null-checks (after the block ending `return@onVariants` at line 180) but **before** the existing variant title / task-name lines (line 182), insert the bundle-mode gate:

```kotlin
            // App Bundle mode and APK instrumentation are mutually exclusive.
            // When bundle mode is enabled, register BundleIntegrityTask on
            // SingleArtifact.BUNDLE and skip the APK transform for this variant.
            val bundleModeEnabled = ext.appBundle.enabled.getOrElse(false)
            if (bundleModeEnabled) {
                project.logger.lifecycle(
                    "io.ssemaj: appBundle.enabled=true — APK integrity transform skipped " +
                        "for variant '${variant.name}'; bundle-mode integrity applies"
                )
                val bundleTitle = variant.name.replaceFirstChar { it.uppercase() }
                val bundleTask = project.tasks.register<BundleIntegrityTask>(
                    "bundle${bundleTitle}DeviceIntelligenceIntegrity",
                ) {
                    group = "io.ssemaj"
                    description = "Bakes bundle-mode fingerprint into the AAB and re-signs it " +
                        "(variant '${variant.name}')."

                    keyFile.set(genKeyTask.flatMap { it.keyFile })
                    keystoreFile.fileValue(cfgStoreFile)
                    keystorePassword.set(cfgStorePassword)
                    keyAlias.set(cfgKeyAlias)
                    if (cfgKeyPassword != null) keyPassword.set(cfgKeyPassword)
                    if (!cfgStoreType.isNullOrBlank()) keystoreType.set(cfgStoreType)
                    playSigningCertSha256.set(ext.appBundle.playSigningCertSha256)
                    variantName.set(variant.name)
                    applicationId.set(variant.applicationId)
                    pluginVersion.set(PLUGIN_VERSION)
                }

                variant.artifacts.use(bundleTask)
                    .wiredWithFiles(
                        BundleIntegrityTask::inputAab,
                        BundleIntegrityTask::outputAab,
                    )
                    .toTransform(SingleArtifact.BUNDLE)

                project.afterEvaluate {
                    if (ext.verbose.getOrElse(false)) {
                        project.logger.lifecycle(
                            "io.ssemaj: registered ${bundleTask.name} (BUNDLE transform)"
                        )
                    }
                }
                return@onVariants   // skip APK transform for this variant
            }
```

Note: `genKeyTask` is declared later in the method (line ~196). You must move `genKeyTask` registration to **before** the bundle-mode gate. Specifically, move the `val genKeyTask = project.tasks.register<GenerateKeyChunksTask>(...)` block and its source-set wiring up to immediately after the signing-material null-checks but before the bundle-mode gate. The gate then references `genKeyTask` (for `keyFile`); the `return@onVariants` exits so the downstream APK tasks are never registered for bundle-mode variants.

- [ ] **Step 3: Verify the plugin compiles**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :deviceintelligence-gradle:compileKotlin 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Verify all plugin tests still pass**

```bash
./gradlew :deviceintelligence-gradle:test 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL (same 6 tests).

- [ ] **Step 5: Smoke-test in the sample (APK mode, no regression)**

```bash
./gradlew :samples:minimal:assembleDebug 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL. The sample's debug build uses APK mode (no `appBundle.enabled`); this verifies the plugin gate doesn't break the existing path.

- [ ] **Step 6: Commit**

```bash
git add \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/tasks/BundleIntegrityTask.kt \
    deviceintelligence-gradle/src/main/kotlin/io/ssemaj/deviceintelligence/gradle/DeviceIntelligencePlugin.kt
git commit -m "feat(bundle): BundleIntegrityTask + plugin gate (SingleArtifact.BUNDLE transform)"
```

---

### Task 5: Native — zlib inflate path + JNI + NativeBridge + host C++ test

**Files:**
- Modify: `deviceintelligence/src/main/cpp/CMakeLists.txt` (lines 64–71)
- Modify: `deviceintelligence/src/main/cpp/dicore/zip_parser.h`
- Modify: `deviceintelligence/src/main/cpp/dicore/zip_parser.cpp`
- Modify: `deviceintelligence/src/main/cpp/dicore/jni_bridge.cpp`
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/NativeBridge.kt`
- Create: `deviceintelligence/src/test/cpp/test_hash_entry_decompressed.cpp`

**Interfaces:**
- Consumes: existing `ApkMap`, `find_central_directory`, `sha::sha256`, `hex::encode`.
- Produces:
  - C++: `bool dicore::zip::hash_entry_decompressed(const ApkMap& apk, const CentralDirInfo& cdi, const char* entry_name, uint8_t out32[32])`
  - JNI: `Java_io_ssemaj_deviceintelligence_internal_NativeBridge_apkEntryDecompressedHash` → `String?`
  - Kotlin: `external fun apkEntryDecompressedHash(path: String, entryName: String): String?`
  - All consumed by Task 6 (`ApkIntegrityDetector`).

- [ ] **Step 1: Write the host C++ test first**

Create `deviceintelligence/src/test/cpp/test_hash_entry_decompressed.cpp`:

```cpp
// Host test for dicore::zip::hash_entry_decompressed.
// Compile: see step 2. Run on x86_64 Android emulator via ADB.
#include "dicore/zip_parser.h"
#include "dicore/apkmap.h"
#include "dicore/sha256.h"
#include "dicore/hex.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <zlib.h>

using namespace dicore;

// ---- Minimal ZIP writer -----------------------------------------------
static void w16(std::vector<uint8_t>& v, uint16_t x) { v.push_back(x&0xFF); v.push_back(x>>8); }
static void w32(std::vector<uint8_t>& v, uint32_t x) { for(int i=0;i<4;i++){v.push_back(x&0xFF);x>>=8;} }

struct CdEntry { std::string name; uint32_t lfh_off, comp_sz, uncomp_sz, crc32v; uint16_t method; };

static uint32_t crc32_buf(const uint8_t* p, size_t n) {
    return (uint32_t)::crc32(::crc32(0L, Z_NULL, 0), p, (uInt)n);
}

static void emit_lfh(std::vector<uint8_t>& v, CdEntry& e) {
    e.lfh_off = (uint32_t)v.size();
    w32(v,0x04034b50u); w16(v,20); w16(v,0); w16(v,e.method);
    w16(v,0); w16(v,0);
    w32(v,e.crc32v); w32(v,e.comp_sz); w32(v,e.uncomp_sz);
    w16(v,(uint16_t)e.name.size()); w16(v,0);
    for(char c:e.name) v.push_back((uint8_t)c);
}

static std::vector<uint8_t> build_zip(
    const char* stored_name, const uint8_t* stored_data, uint32_t stored_len,
    const char* deflated_name, const uint8_t* plain, uint32_t plain_len)
{
    std::vector<uint8_t> zip;
    std::vector<CdEntry> entries;

    // STORED entry
    {
        CdEntry e; e.name=stored_name; e.method=0;
        e.uncomp_sz=stored_len; e.comp_sz=stored_len;
        e.crc32v=crc32_buf(stored_data,stored_len);
        emit_lfh(zip,e);
        for(uint32_t i=0;i<stored_len;i++) zip.push_back(stored_data[i]);
        entries.push_back(e);
    }

    // DEFLATED entry — raw deflate (no zlib header)
    {
        std::vector<uint8_t> comp(compressBound(plain_len));
        z_stream zs{}; deflateInit2(&zs,Z_DEFAULT_COMPRESSION,Z_DEFLATED,-MAX_WBITS,8,Z_DEFAULT_STRATEGY);
        zs.next_in=const_cast<Bytef*>(plain); zs.avail_in=plain_len;
        zs.next_out=comp.data(); zs.avail_out=(uInt)comp.size();
        deflate(&zs,Z_FINISH); uint32_t csz=(uint32_t)zs.total_out; deflateEnd(&zs);

        CdEntry e; e.name=deflated_name; e.method=8;
        e.uncomp_sz=plain_len; e.comp_sz=csz;
        e.crc32v=crc32_buf(plain,plain_len);
        emit_lfh(zip,e);
        for(uint32_t i=0;i<csz;i++) zip.push_back(comp[i]);
        entries.push_back(e);
    }

    // Central directory
    uint32_t cd_start=(uint32_t)zip.size();
    for(auto& e:entries){
        w32(zip,0x02014b50u); w16(zip,20); w16(zip,20); w16(zip,0); w16(zip,e.method);
        w16(zip,0); w16(zip,0);
        w32(zip,e.crc32v); w32(zip,e.comp_sz); w32(zip,e.uncomp_sz);
        w16(zip,(uint16_t)e.name.size()); w16(zip,0); w16(zip,0);
        w16(zip,0); w16(zip,0); w32(zip,0); w32(zip,e.lfh_off);
        for(char c:e.name) zip.push_back((uint8_t)c);
    }
    uint32_t cd_sz=(uint32_t)zip.size()-cd_start;
    w32(zip,0x06054b50u); w16(zip,0); w16(zip,0);
    w16(zip,(uint16_t)entries.size()); w16(zip,(uint16_t)entries.size());
    w32(zip,cd_sz); w32(zip,cd_start); w16(zip,0);
    return zip;
}

static std::string sha256_hex_of(const void* p, size_t n) {
    uint8_t md[32];
    sha::sha256(p, n, md);
    return hex::encode(md,32);
}

static void write_file(const char* path, const std::vector<uint8_t>& data) {
    FILE* f=fopen(path,"wb"); assert(f);
    fwrite(data.data(),1,data.size(),f); fclose(f);
}

int main() {
    // Init SHA backend (dlopen BoringSSL on Android)
    assert(sha::ensure_initialized());

    const char STORED_DATA[] = "STORED_PAYLOAD_BYTES_FOR_TESTING";
    const uint32_t STORED_LEN = (uint32_t)strlen(STORED_DATA);
    const char DEFLATED_DATA[] = "DEFLATED_PAYLOAD_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const uint32_t DEFLATED_LEN = (uint32_t)strlen(DEFLATED_DATA);

    auto zip = build_zip(
        "stored.txt",   (const uint8_t*)STORED_DATA,   STORED_LEN,
        "deflated.txt", (const uint8_t*)DEFLATED_DATA, DEFLATED_LEN
    );
    const char* path = "/data/local/tmp/di_test_inflate.zip";
    write_file(path, zip);

    ApkMap apk; assert(apk.open(path));
    zip::CentralDirInfo cdi; assert(zip::find_central_directory(apk, &cdi));

    // Test 1: STORED entry — hash equals SHA-256 of the plain bytes
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, "stored.txt", out);
        assert(ok);
        std::string want = sha256_hex_of(STORED_DATA, STORED_LEN);
        std::string got  = hex::encode(out, 32);
        assert(want == got && "Test1 STORED hash mismatch");
        printf("PASS test1: STORED hash = %s\n", got.c_str());
    }

    // Test 2: DEFLATED entry — hash equals SHA-256 of the INFLATED (plain) bytes
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, "deflated.txt", out);
        assert(ok);
        std::string want = sha256_hex_of(DEFLATED_DATA, DEFLATED_LEN);
        std::string got  = hex::encode(out, 32);
        assert(want == got && "Test2 DEFLATED hash mismatch (got compressed hash?)");
        printf("PASS test2: DEFLATED decompressed hash = %s\n", got.c_str());
    }

    // Test 3: missing entry returns false, no crash
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, "does_not_exist.bin", out);
        assert(!ok && "Test3 missing entry should return false");
        printf("PASS test3: missing entry returns false\n");
    }

    // Test 4: null entry_name returns false, no crash
    {
        uint8_t out[32];
        bool ok = zip::hash_entry_decompressed(apk, cdi, nullptr, out);
        assert(!ok && "Test4 null entry_name should return false");
        printf("PASS test4: null entry_name returns false\n");
    }

    // Test 5: garbage file (not a ZIP) — find_central_directory fails
    {
        const char* bad = "/data/local/tmp/di_garbage.bin";
        {FILE* f=fopen(bad,"wb"); const char g[]={0xDE,0xAD,0xBE,0xEF,0x00}; fwrite(g,1,4,f); fclose(f);}
        ApkMap bad_apk; bad_apk.open(bad);
        zip::CentralDirInfo bad_cdi;
        bool has_cd = zip::find_central_directory(bad_apk, &bad_cdi);
        if (has_cd) {
            uint8_t out[32];
            bool ok = zip::hash_entry_decompressed(bad_apk, bad_cdi, "anything", out);
            assert(!ok);
        }
        printf("PASS test5: garbage file handled safely (has_cd=%d)\n", (int)has_cd);
    }

    printf("ALL TESTS PASSED\n");
    return 0;
}
```

- [ ] **Step 2: Compile and run the test (expect FAIL — `hash_entry_decompressed` not yet declared)**

```bash
CLANG=$HOME/Android/Sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang++
SRC=/home/joseph/AndroidStudioProjects/DeviceIntelligence/deviceintelligence/src/main/cpp
TSRC=/home/joseph/AndroidStudioProjects/DeviceIntelligence/deviceintelligence/src/test/cpp
mkdir -p $TSRC
$CLANG -std=c++17 -Wall -Wextra -Werror \
    -I$SRC \
    $SRC/dicore/zip_parser.cpp \
    $SRC/dicore/apkmap.cpp \
    $SRC/dicore/sha256.cpp \
    $SRC/dicore/hex.cpp \
    $SRC/dicore/syscalls.cpp \
    $TSRC/test_hash_entry_decompressed.cpp \
    -llog -lz -pie -fPIE \
    -o /tmp/di_test_inflate 2>&1 | tail -20
```

Expected: compile error — `hash_entry_decompressed` not declared.

- [ ] **Step 3: Modify `CMakeLists.txt` — link zlib**

In `deviceintelligence/src/main/cpp/CMakeLists.txt`, after `find_library(android-lib android)` (line 65), add:

```cmake
find_library(z-lib z)
```

In the `target_link_libraries(dicore ...)` block (lines 67–70), add `${z-lib}`:

```cmake
target_link_libraries(dicore
        ${log-lib}
        ${android-lib}
        ${z-lib}
        dl
)
```

- [ ] **Step 4: Add `hash_entry_decompressed` declaration to `zip_parser.h`**

In `deviceintelligence/src/main/cpp/dicore/zip_parser.h`, after the `hash_all_entries` declaration (line 44), add:

```cpp
// Hash the DECOMPRESSED body of the ZIP entry named `entry_name`.
// For STORED entries, SHA-256 the raw body directly.
// For DEFLATED entries, inflate via NDK zlib (raw deflate, inflateInit2(-MAX_WBITS))
// into a bounded buffer and SHA-256 the inflated bytes.
// Writes 32 bytes to out32 on success and returns true.
// Returns false (fail-closed, no crash) if: entry not found, null entry_name,
// ZIP64 sentinel, zlib error, inflated size > 64 MB guard, or body out of range.
bool hash_entry_decompressed(const ApkMap& apk,
                             const CentralDirInfo& cdi,
                             const char* entry_name,
                             uint8_t out32[32]);
```

- [ ] **Step 5: Implement `hash_entry_decompressed` in `zip_parser.cpp`**

At the top of `zip_parser.cpp`, after `#include <cstring>`, add:

```cpp
#include <vector>
#include <zlib.h>
```

Inside the anonymous namespace in `zip_parser.cpp`, add the inflate guard constant:

```cpp
// Maximum decompressed entry size accepted by hash_entry_decompressed.
// Entries larger than this are skipped (fail-closed). 64 MB covers the
// largest realistic dex/so in production; a real tamper attempt has no
// incentive to inflate to this size.
constexpr size_t kMaxInflateBytes = 64u * 1024u * 1024u;
```

After the closing brace of `hash_all_entries` (line 173), before the closing `} // namespace dicore::zip`, add:

```cpp
bool hash_entry_decompressed(const ApkMap& apk,
                             const CentralDirInfo& cdi,
                             const char* entry_name,
                             uint8_t out32[32]) {
    if (!cdi.present || !entry_name) return false;

    const uint8_t* cd = apk.range((size_t)cdi.cd_offset, (size_t)cdi.cd_size);
    if (!cd) return false;

    size_t cd_off = 0;
    for (uint64_t i = 0; i < cdi.total_entries; ++i) {
        if (cd_off + kCdfhMinSize > (size_t)cdi.cd_size) break;
        const uint8_t* p = cd + cd_off;
        if (rd32(p) != kCdfhMagic) break;

        uint16_t method    = rd16(p + 10);
        uint32_t comp      = rd32(p + 20);
        uint32_t uncomp    = rd32(p + 24);
        uint16_t name_len  = rd16(p + 28);
        uint16_t extra_len = rd16(p + 30);
        uint16_t cmt_len   = rd16(p + 32);
        uint32_t lfh_off   = rd32(p + 42);

        size_t total_var = (size_t)name_len + extra_len + cmt_len;
        if (cd_off + kCdfhMinSize + total_var > (size_t)cdi.cd_size) break;

        std::string_view name(reinterpret_cast<const char*>(p + kCdfhMinSize), name_len);

        if (name == entry_name) {
            // ZIP64 sentinel guard — skip rather than misinterpret.
            if (comp == 0xFFFFFFFFu || uncomp == 0xFFFFFFFFu) {
                RLOGW("zip: hash_entry_decompressed: ZIP64 entry '%s', skipping", entry_name);
                return false;
            }

            // Resolve body offset via LFH (LFH and CDFH extra fields may differ).
            const uint8_t* lfh = apk.range(lfh_off, kLfhMinSize);
            if (!lfh || rd32(lfh) != kLfhMagic) return false;
            uint16_t lfh_name_len  = rd16(lfh + 26);
            uint16_t lfh_extra_len = rd16(lfh + 28);
            uint64_t body_off = (uint64_t)lfh_off + kLfhMinSize
                                + lfh_name_len + lfh_extra_len;

            if (method == 0 /* STORED */) {
                const uint8_t* body = apk.range((size_t)body_off, (size_t)comp);
                if (!body) return false;
                return sha::sha256(body, (size_t)comp, out32);
            }

            if (method == 8 /* DEFLATED */) {
                if (uncomp > kMaxInflateBytes) {
                    RLOGW("zip: hash_entry_decompressed: uncomp_size %u > limit for '%s'",
                          uncomp, entry_name);
                    return false;
                }

                const uint8_t* comp_body = apk.range((size_t)body_off, (size_t)comp);
                if (!comp_body) return false;

                std::vector<uint8_t> inflated((size_t)uncomp);

                z_stream zs{};
                // -MAX_WBITS = raw deflate (no zlib/gzip header).
                if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;

                zs.next_in   = const_cast<Bytef*>(comp_body);
                zs.avail_in  = comp;
                zs.next_out  = inflated.data();
                zs.avail_out = uncomp;

                int ret = inflate(&zs, Z_FINISH);
                inflateEnd(&zs);

                if (ret != Z_STREAM_END) {
                    RLOGW("zip: hash_entry_decompressed: inflate ret=%d for '%s'",
                          ret, entry_name);
                    return false;
                }
                if (zs.total_out != (uLong)uncomp) {
                    RLOGW("zip: hash_entry_decompressed: inflate wrote %lu of %u for '%s'",
                          (unsigned long)zs.total_out, uncomp, entry_name);
                    return false;
                }

                return sha::sha256(inflated.data(), (size_t)uncomp, out32);
            }

            RLOGW("zip: hash_entry_decompressed: unsupported method %u for '%s'",
                  method, entry_name);
            return false;
        }

        cd_off += kCdfhMinSize + total_var;
    }
    return false; // entry not found
}
```

- [ ] **Step 6: Compile the test and verify it builds**

```bash
CLANG=$HOME/Android/Sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android35-clang++
SRC=/home/joseph/AndroidStudioProjects/DeviceIntelligence/deviceintelligence/src/main/cpp
TSRC=/home/joseph/AndroidStudioProjects/DeviceIntelligence/deviceintelligence/src/test/cpp
$CLANG -std=c++17 -Wall -Wextra -Werror \
    -I$SRC \
    $SRC/dicore/zip_parser.cpp \
    $SRC/dicore/apkmap.cpp \
    $SRC/dicore/sha256.cpp \
    $SRC/dicore/hex.cpp \
    $SRC/dicore/syscalls.cpp \
    $TSRC/test_hash_entry_decompressed.cpp \
    -llog -lz -pie -fPIE \
    -o /tmp/di_test_inflate 2>&1
```

Expected: clean compile, no errors/warnings. The `-Werror` flag treats all warnings as errors.

- [ ] **Step 7: Push and run on x86_64 emulator**

Ensure an x86_64 Android emulator is running, then:

```bash
adb push /tmp/di_test_inflate /data/local/tmp/
adb shell chmod +x /data/local/tmp/di_test_inflate
adb shell /data/local/tmp/di_test_inflate
```

Expected output:
```
PASS test1: STORED hash = <64-char hex>
PASS test2: DEFLATED decompressed hash = <64-char hex>
PASS test3: missing entry returns false
PASS test4: null entry_name returns false
PASS test5: garbage file handled safely (has_cd=0)
ALL TESTS PASSED
```

If `test2`'s hash matches `test1`'s, the function is accidentally hashing the compressed bytes — debug the inflate path.

- [ ] **Step 8: Add `apkEntryDecompressedHash` JNI function to `jni_bridge.cpp`**

In `deviceintelligence/src/main/cpp/dicore/jni_bridge.cpp`, after the closing brace of `Java_io_ssemaj_deviceintelligence_internal_NativeBridge_apkSignerCertHashes` (currently the last function, around line 102), before `} // extern "C"`, add:

```cpp
JNIEXPORT jstring JNICALL
Java_io_ssemaj_deviceintelligence_internal_NativeBridge_apkEntryDecompressedHash(
        JNIEnv* env, jclass, jstring jpath, jstring jentry) {
    if (!jpath || !jentry) return nullptr;

    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return nullptr;
    const char* entry = env->GetStringUTFChars(jentry, nullptr);
    if (!entry) {
        env->ReleaseStringUTFChars(jpath, path);
        return nullptr;
    }

    ApkMap apk;
    bool ok = apk.open(path);
    env->ReleaseStringUTFChars(jpath, path);
    if (!ok) {
        RLOGE("apkEntryDecompressedHash: open failed for entry '%s'", entry);
        env->ReleaseStringUTFChars(jentry, entry);
        return nullptr;
    }

    zip::CentralDirInfo cdi;
    if (!zip::find_central_directory(apk, &cdi)) {
        env->ReleaseStringUTFChars(jentry, entry);
        return nullptr;
    }

    uint8_t md[sha::kDigestLen];
    bool found = zip::hash_entry_decompressed(apk, cdi, entry, md);
    env->ReleaseStringUTFChars(jentry, entry);
    if (!found) return nullptr;

    return make_jstring(env, hex::encode(md, sha::kDigestLen));
}
```

- [ ] **Step 9: Add `apkEntryDecompressedHash` to `NativeBridge.kt`**

In `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/NativeBridge.kt`, after the `apkSignerCertHashes` declaration (around line 56), add:

```kotlin
    /**
     * Returns the SHA-256 hex of the DECOMPRESSED body of the ZIP entry named
     * [entryName] inside the APK/split at [path]. Returns null if the entry
     * is not found, the APK can't be opened, or inflate fails (fail-closed to
     * not-found, not a crash). Used by [ApkIntegrityDetector] in bundle mode
     * to compare decompressed code entry hashes across base + split APKs.
     */
    @JvmStatic
    external fun apkEntryDecompressedHash(path: String, entryName: String): String?
```

- [ ] **Step 10: Verify the full native build succeeds**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :samples:minimal:assembleDebug 2>&1 | tail -30
```

Expected: BUILD SUCCESSFUL. Check that `libdicore.so` is built without warnings (the `-Werror` flag catches silent issues).

- [ ] **Step 11: Commit**

```bash
git add \
    deviceintelligence/src/main/cpp/CMakeLists.txt \
    deviceintelligence/src/main/cpp/dicore/zip_parser.h \
    deviceintelligence/src/main/cpp/dicore/zip_parser.cpp \
    deviceintelligence/src/main/cpp/dicore/jni_bridge.cpp \
    deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/NativeBridge.kt \
    deviceintelligence/src/test/cpp/test_hash_entry_decompressed.cpp
git commit -m "feat(bundle): native hash_entry_decompressed via NDK zlib + JNI apkEntryDecompressedHash"
```

---

### Task 6: Runtime `ApkIntegrityDetector` Bundle Branch

**Files:**
- Modify: `deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/ApkIntegrityDetector.kt`

**Interfaces:**
- Consumes: `Fingerprint.bundleMode`, `Fingerprint.bundleEntryHashes`, `Fingerprint.signerCertSha256` (allow-set semantics), `NativeBridge.apkSignerCertHashes()`, `NativeBridge.apkEntryDecompressedHash()`, `applicationInfo.sourceDir`, `applicationInfo.splitSourceDirs`.
- Produces: `Finding("apk_signer_mismatch", CRITICAL)` when an observed cert is not in the allow-set; `Finding("apk_entry_modified", CRITICAL)` on hash mismatch; `Finding("apk_entry_removed", HIGH)` when an entry is absent across all splits.

- [ ] **Step 1: Identify the insertion point in `ApkIntegrityDetector.evaluate()`**

Read the current `evaluate()` method. The APK path is read at line 102. The signer and entry reads follow at lines 110–125. The diff at lines 128–218 uses APK-mode equality checks. The bundle branch must replace lines 110–218 entirely when `baked.bundleMode == true`.

The insertion structure:

```
val apkPath = context.applicationInfo.sourceDir ?: return inconclusive(...)
// [NEW] branch here:
if (baked.bundleMode) {
    // bundle branch (new code)
    return ok(id, findings, dur())
} else {
    // existing APK-mode code (lines 110–218, unchanged)
}
```

- [ ] **Step 2: Write the bundle branch**

In `ApkIntegrityDetector.kt`, after the `val apkPath = ...` line (around line 102), replace the existing code from `val runtimeCerts = NativeBridge.apkSignerCertHashes(apkPath)` down through `return ok(id, findings, dur())` with the following if-else:

```kotlin
        val findings = ArrayList<Finding>(8)

        if (baked.bundleMode) {
            // ---- Bundle mode: signer membership + decompressed entry diff across splits ----

            // Signal 1 — signer membership. Each cert observed in base.apk
            // must be a member of the baked allow-set. If the allow-set is
            // empty (developer baked no certs), the check is skipped — documented
            // fail-open for that edge case; dex/so hashing is then the sole anchor.
            if (baked.signerCertSha256.isNotEmpty()) {
                val allowSet = baked.signerCertSha256.toHashSet()
                val observedCerts = NativeBridge.apkSignerCertHashes(apkPath)
                    ?: return inconclusive(
                        id = id,
                        reason = "apk_unreadable",
                        message = "apkSignerCertHashes returned null for $apkPath",
                        durationMs = dur(),
                    )
                for (cert in observedCerts) {
                    if (cert !in allowSet) {
                        findings += Finding(
                            kind = "apk_signer_mismatch",
                            severity = Severity.CRITICAL,
                            subject = context.packageName,
                            message = "Bundle signer cert is not in the build-time allow-set",
                            details = mapOf(
                                "allow_set" to baked.signerCertSha256.joinToString(","),
                                "observed_cert" to cert,
                            ),
                        )
                    }
                }
            }

            // Source-dir prefix check (same as APK mode).
            if (!apkPath.startsWith(baked.expectedSourceDirPrefix)) {
                findings += Finding(
                    kind = "apk_source_dir_unexpected",
                    severity = Severity.MEDIUM,
                    subject = apkPath,
                    message = "Installed APK lives outside the expected path prefix",
                    details = mapOf(
                        "expected_prefix" to baked.expectedSourceDirPrefix,
                        "observed_path" to apkPath,
                    ),
                )
            }

            // Signal 2 — decompressed code-entry integrity across base + all splits.
            // For each baked entry (key = APK-relative name, value = expected SHA-256),
            // search base.apk then every split APK for the first non-null decompressed hash.
            val splitPaths: List<String> =
                context.applicationInfo.splitSourceDirs?.toList() ?: emptyList()
            val searchPaths: List<String> = listOf(apkPath) + splitPaths

            for ((entryName, expectedHash) in baked.bundleEntryHashes) {
                val observedHash: String? = searchPaths.firstNotNullOfOrNull { splitPath ->
                    NativeBridge.apkEntryDecompressedHash(splitPath, entryName)
                }
                when {
                    observedHash == null -> findings += Finding(
                        kind = "apk_entry_removed",
                        severity = Severity.HIGH,
                        subject = entryName,
                        message = "Bundle entry was present at build time but is absent across all splits",
                        details = mapOf("expected_hash" to expectedHash),
                    )
                    observedHash != expectedHash -> findings += Finding(
                        kind = "apk_entry_modified",
                        severity = Severity.CRITICAL,
                        subject = entryName,
                        message = "Bundle entry's decompressed bytes differ from build time",
                        details = mapOf(
                            "expected_hash" to expectedHash,
                            "observed_hash" to observedHash,
                        ),
                    )
                }
            }

        } else {
            // ---- APK mode: existing equality checks (unchanged) ----
            val runtimeCerts = NativeBridge.apkSignerCertHashes(apkPath)
                ?: return inconclusive(
                    id = id,
                    reason = "apk_unreadable",
                    message = "apkSignerCertHashes returned null for $apkPath",
                    durationMs = dur(),
                )

            val runtimeEntriesArr = NativeBridge.apkEntries(apkPath)
                ?: return inconclusive(
                    id = id,
                    reason = "apk_unreadable",
                    message = "apkEntries returned null for $apkPath",
                    durationMs = dur(),
                )
            val runtimeEntries = parseEntryArray(runtimeEntriesArr)

            val expectedCerts = baked.signerCertSha256.toSet()
            val observedCerts = runtimeCerts.toSet()
            if (observedCerts != expectedCerts) {
                findings += Finding(
                    kind = "apk_signer_mismatch",
                    severity = Severity.CRITICAL,
                    subject = context.packageName,
                    message = "APK signer cert(s) differ from the build-time baked set",
                    details = mapOf(
                        "expected" to baked.signerCertSha256.joinToString(","),
                        "observed" to runtimeCerts.joinToString(","),
                    ),
                )
            }

            if (!apkPath.startsWith(baked.expectedSourceDirPrefix)) {
                findings += Finding(
                    kind = "apk_source_dir_unexpected",
                    severity = Severity.MEDIUM,
                    subject = apkPath,
                    message = "Installed APK lives outside the expected path prefix",
                    details = mapOf(
                        "expected_prefix" to baked.expectedSourceDirPrefix,
                        "observed_path" to apkPath,
                    ),
                )
            }

            if (baked.expectedInstallerWhitelist.isNotEmpty()) {
                val installer = readInstallerPackageName(context)
                if (installer == null || installer !in baked.expectedInstallerWhitelist) {
                    findings += Finding(
                        kind = "installer_not_whitelisted",
                        severity = Severity.MEDIUM,
                        subject = installer,
                        message = "Installer package is not in the baked whitelist",
                        details = mapOf(
                            "whitelist" to baked.expectedInstallerWhitelist.joinToString(","),
                            "observed_installer" to (installer ?: "<null>"),
                        ),
                    )
                }
            }

            val ignoredEntries = baked.ignoredEntries.toHashSet()
            val ignoredPrefixes = baked.ignoredEntryPrefixes
            val filteredRuntime = HashMap<String, String>(runtimeEntries.size)
            for ((name, hash) in runtimeEntries) {
                if (name in ignoredEntries) continue
                if (ignoredPrefixes.any { name.startsWith(it) }) continue
                filteredRuntime[name] = hash
            }

            for ((name, expectedHash) in baked.entries) {
                val observedHash = filteredRuntime[name]
                when {
                    observedHash == null -> findings += Finding(
                        kind = "apk_entry_removed",
                        severity = Severity.HIGH,
                        subject = name,
                        message = "APK entry was present at build time but is missing at runtime",
                        details = mapOf("expected_hash" to expectedHash),
                    )
                    observedHash != expectedHash -> findings += Finding(
                        kind = "apk_entry_modified",
                        severity = Severity.CRITICAL,
                        subject = name,
                        message = "APK entry exists but its bytes differ from build time",
                        details = mapOf(
                            "expected_hash" to expectedHash,
                            "observed_hash" to observedHash,
                        ),
                    )
                }
            }
            for ((name, observedHash) in filteredRuntime) {
                if (name !in baked.entries) {
                    findings += Finding(
                        kind = "apk_entry_added",
                        severity = Severity.HIGH,
                        subject = name,
                        message = "APK entry exists at runtime but wasn't present at build time",
                        details = mapOf("observed_hash" to observedHash),
                    )
                }
            }
        }

        return ok(id, findings, dur())
```

Also delete the now-redundant `val findings = ArrayList<Finding>(4)` line that was previously at line 128 (we replaced it with `val findings = ArrayList<Finding>(8)` at the top of the new branch).

- [ ] **Step 3: Verify the runtime module compiles**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :deviceintelligence:compileReleaseKotlin 2>&1 | tail -20
```

Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Verify the full sample builds (APK mode regression check)**

```bash
./gradlew :samples:minimal:assembleRelease 2>&1 | tail -30
```

Expected: BUILD SUCCESSFUL with `instrument*` tasks running (not bundle tasks).

- [ ] **Step 5: Commit**

```bash
git add deviceintelligence/src/main/kotlin/io/ssemaj/deviceintelligence/internal/ApkIntegrityDetector.kt
git commit -m "feat(bundle): ApkIntegrityDetector bundle branch — signer membership + decompressed entry diff"
```

---

### Task 7: On-Device Validation (User / Device Task)

**This task is entirely manual. No code is written or committed.**

**Prerequisites:** Tasks 1–6 merged to main. The attached test device (clean Xiaomi 2512BPNDAG, API 36) or the x86_64 emulator. `bundletool` installed and on `$PATH` (`bundletool --version` prints without error). The `samples/minimal` project configured with a valid release signing config (`signingConfigs.release`) and `appBundle { enabled = true }` in its `deviceintelligence` block.

**Step A: Configure the sample for bundle mode**

In `samples/minimal/build.gradle.kts` (or your consumer app), add under `deviceintelligence { ... }`:

```kotlin
deviceintelligence {
    appBundle {
        enabled = true
        // Add Play App Signing cert if you have it. For local bundletool testing,
        // the upload key is used for both signing and installation — it is in
        // the allow-set by default (via signerCertHashes in BundleFingerprintBuilder).
        // playSigningCertSha256("YOUR_PLAY_SIGNING_CERT_SHA256")
    }
}
```

**Step B: Build the `.aab`**

```bash
export JAVA_HOME=/home/joseph/.jdks/temurin-23.0.2
./gradlew :samples:minimal:bundleRelease
```

Verify the task `bundleReleaseDeviceIntelligenceIntegrity` ran (check gradle output). Locate the output AAB:
```
samples/minimal/build/outputs/bundle/release/minimal-release.aab
```

**Step C: Install via bundletool (local testing — upload key signs)**

```bash
bundletool build-apks \
    --bundle=samples/minimal/build/outputs/bundle/release/minimal-release.aab \
    --output=/tmp/minimal.apks \
    --ks=<path-to-upload.jks> \
    --ks-pass=pass:<password> \
    --ks-key-alias=<alias> \
    --key-pass=pass:<key-password> \
    --local-testing

bundletool install-apks --apks=/tmp/minimal.apks
```

(Alternatively: `--mode=universal` → `install-apks` → single universal APK sideloaded.)

**Step D: Launch and observe — zero false positives**

Launch the sample on device. Open Logcat, filter by `DeviceIntelligence`:

```bash
adb logcat -s DeviceIntelligence.ApkIntegrity
```

Expected: no `fingerprint_asset_missing`, no `apk_signer_mismatch`, no `apk_entry_modified`, no `apk_entry_removed`. The telemetry report should be CLEAN.

**Step E: Tamper test — verify detection**

Two options (pick one):

**Option 1: Flip a baked hash.** After `bundleRelease`, in the emitted AAB, locate the `base/assets/io.ssemaj.deviceintelligence/fingerprint.bin`, corrupt it (e.g., flip a byte at offset 64), re-pack, re-sign with a test key. Reinstall. Expected: `fingerprint_bad_magic` or `fingerprint_corrupt` CRITICAL finding.

**Option 2: Patch a dex in a split.** Using `bundletool build-apks --mode=universal`, extract the universal APK, patch one byte inside `classes.dex` using a hex editor, repack and sideload. Expected: `apk_entry_modified` CRITICAL finding for `classes.dex`.

**Verify detection in Logcat:**
```bash
adb logcat -s DeviceIntelligence.ApkIntegrity | grep -E "CRITICAL|entry_modified|signer_mismatch"
```

Expected: at least one CRITICAL finding matching the tamper. No false positives on the clean install (Step D).

---

## Self-Review

### Spec Coverage Check

| Spec requirement | Task covering it |
|---|---|
| AppBundleOptions DSL: `enabled`, `playSigningCertSha256(vararg)`, normalize (strip `:`, lowercase) | Task 1 |
| `DeviceIntelligenceExtension` `@Nested appBundle` + DSL sugar | Task 1 |
| Plugin `Fingerprint` v3: `bundleMode`, `bundleEntryHashes`, SCHEMA_VERSION 2→3 | Task 2 |
| Plugin `FingerprintCodec` FORMAT_VERSION 2→3, v3 encode + decode | Task 2 |
| Runtime `Fingerprint` v3 fields | Task 2 |
| Runtime `FingerprintCodec` FORMAT_VERSION 2→3, v3 decode | Task 2 |
| `MIN_SUPPORTED_FORMAT_VERSION` stays 1 | Task 2 (verified by existing v2-blob test) |
| `AabHasher.bundleEntryHashes` — decompressed SHA-256, normalization | Task 3 |
| `AabSigner.sign` — JDK JarSigner, no bundletool | Task 3 |
| `KeystoreSigning` shared helper (DRY) | Task 3 |
| `BundleFingerprintBuilder.build` — DI XOR encryption | Task 3 |
| `BundleIntegrityTask` — BUNDLE transform, repack (no dir entries), sign | Task 4 |
| Plugin gate: `bundleMode=true` → skip APK transform | Task 4 |
| Plugin gate: `bundleMode=false` → unchanged APK path | Task 4 (smoke test) |
| CMake: `find_library(z-lib z)` + link | Task 5 |
| `hash_entry_decompressed`: STORED path | Task 5 |
| `hash_entry_decompressed`: DEFLATED path via `inflateInit2(-MAX_WBITS)` | Task 5 |
| `hash_entry_decompressed`: bounds-check, fail-closed (no crash) | Task 5 |
| `hash_entry_decompressed`: 64 MB inflate guard | Task 5 |
| JNI `apkEntryDecompressedHash` | Task 5 |
| `NativeBridge.apkEntryDecompressedHash` | Task 5 |
| Host C++ test: STORED + DEFLATED + missing + garbage | Task 5 |
| Runtime bundle branch: signer membership (skip if allow-set empty) | Task 6 |
| Runtime bundle branch: decompressed entry diff across `sourceDir + splitSourceDirs` | Task 6 |
| Runtime: `apk_signer_mismatch` CRITICAL on non-member cert | Task 6 |
| Runtime: `apk_entry_modified` CRITICAL on hash mismatch | Task 6 |
| Runtime: `apk_entry_removed` HIGH on absent entry | Task 6 |
| Runtime: keep `expectedSourceDirPrefix` check | Task 6 |
| Runtime: keep `dicoreTextSha256ByAbi` / `nativeLibInventoryByAbi` push unchanged | Task 6 (not touched) |
| Device validation: zero false positives with bundletool local install | Task 7 |
| Tamper test: `apk_entry_modified` CRITICAL fires | Task 7 |
| No `apk_entry_added` in bundle mode | Task 6 (bundle branch has no added-entry loop) |
| Resources/manifest not byte-pinned in bundle mode | AabHasher excludes them (Task 3) |

### Placeholder Scan

No "TBD", "TODO", or "implement later" present. All code steps include complete implementation. All test steps include the exact assertion and command. All file paths are absolute or relative from the repo root with enough context to locate them.

### Type Consistency Verification

- `KeystoreSigning.Material.privateKey: PrivateKey` → consumed by `AabSigner.sign(aab, key, certs)` (Task 3) and `BundleIntegrityTask.run()` (Task 4). ✓
- `KeystoreSigning.Material.certs: List<X509Certificate>` → same consumers. ✓
- `KeystoreSigning.Material.certHashes: List<String>` → `BundleFingerprintBuilder.build(signerCertHashes=...)` (Task 3, 4). ✓
- `BundleFingerprintBuilder.build(key: ByteArray, ...)` → `BundleIntegrityTask` passes `keyFile.get().asFile.readBytes()` (Task 4). ✓
- `AabHasher.bundleEntryHashes(aab: File): Map<String, String>` → consumed by `BundleFingerprintBuilder.build` (Task 3). ✓
- `AabSigner.sign(aab: File, key: PrivateKey, certs: List<X509Certificate>)` → `BundleIntegrityTask.run()` (Task 4). ✓
- `Fingerprint.bundleMode: Boolean` → `ApkIntegrityDetector.evaluate()` checks `baked.bundleMode` (Task 6). ✓
- `Fingerprint.bundleEntryHashes: Map<String, String>` → `ApkIntegrityDetector` iterates (Task 6). ✓
- `NativeBridge.apkEntryDecompressedHash(path: String, entryName: String): String?` → `ApkIntegrityDetector` calls (Task 6). ✓
- `zip::hash_entry_decompressed(apk, cdi, entry_name, out32)` → JNI function calls it (Task 5). ✓
- Plugin `FingerprintCodec.FORMAT_VERSION = 3` → runtime `FingerprintCodec.FORMAT_VERSION = 3`; both accept 1..3. ✓
- `BundleIntegrityTask.BUNDLE_ASSET_PATH = "base/" + Fingerprint.ASSET_PATH` → `injectAsset` injects at that path; runtime `FingerprintAssetReader.readEncryptedBytes(context)` reads `Fingerprint.ASSET_PATH` from APK assets (deployed from base module). ✓
