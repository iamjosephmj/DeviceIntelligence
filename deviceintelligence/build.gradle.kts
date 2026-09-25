import tech.thessemaj.deviceintelligence.buildtools.BaselineBlob
import java.security.MessageDigest
import com.vanniktech.maven.publish.AndroidSingleVariantLibrary

plugins {
    id("deviceintelligence.android.library")
    `maven-publish`
    id("com.vanniktech.maven.publish") version "0.34.0"
}

// Read coordinates from gradle.properties so JitPack (which sets
// VERSION_NAME from the git tag) and `publishToMavenLocal` (used
// for smoke-testing) share the same source of truth.
val publishGroup: String = providers.gradleProperty("GROUP_ID").get()
val publishVersion: String = providers.gradleProperty("VERSION_NAME").get()
val libraryArtifactId: String = providers.gradleProperty("LIBRARY_ARTIFACT_ID").get()

group = publishGroup
version = publishVersion

// Release hardening gate: releases must go through the OLLVM launcher
// (tools/obfuscator/ollvm-launch.sh), which is auto-detected when present.
// Explicit -Pdeviceintelligence.obfuscate=<launcher> wins;
// -Pdeviceintelligence.allowUnobfuscatedRelease=true opts out.
val diObfuscateProperty = project.findProperty("deviceintelligence.obfuscate") as String?
val allowUnobfuscatedRelease =
        (project.findProperty("deviceintelligence.allowUnobfuscatedRelease") as String?) == "true"
val obfRoot = rootProject.projectDir.resolve("tools/obfuscator")
val obfLauncher: File? =
        diObfuscateProperty?.let { rootProject.file(it) }
                ?: obfRoot.resolve("ollvm-launch.sh").takeIf { launcher ->
                    !allowUnobfuscatedRelease && launcher.exists()
                }
if (!allowUnobfuscatedRelease) {
    gradle.taskGraph.whenReady {
        val releasesDeviceIntelligence = allTasks.any {
            // "Clean" tasks are pure deletion — they can't ship an
            // unhardened artifact, so only compiling/packaging tasks gate.
            it.project.path == ":deviceintelligence" && it.name.contains("Release") &&
                    !it.name.contains("Clean", ignoreCase = true)
        }
        if (releasesDeviceIntelligence && obfLauncher == null) {
            throw GradleException(
                "deviceintelligence: release build without the OLLVM launcher would ship an " +
                        "unobfuscated libdicore.so (plaintext detector strings, recoverable " +
                        "control flow). tools/obfuscator/ollvm-launch.sh is missing — restore it " +
                        "and ensure the ollvm17 clang exists at " +
                        "~/AndroidStudioProjects/_ollvm/ollvm17/build/bin/clang (see " +
                        "tools/obfuscator/README.md), or pass " +
                        "-Pdeviceintelligence.obfuscate=<launcher> / " +
                        "-Pdeviceintelligence.allowUnobfuscatedRelease=true to opt out explicitly.",
            )
        }
    }
}

android {
    namespace = "tech.thessemaj.deviceintelligence"
    ndkVersion = "27.0.12077973"

    defaultConfig {
        // Android 9 is the floor: the F14 hardware key-attestation
        // surface and several PackageManager APIs we rely on
        // (GET_SIGNING_CERTIFICATES, signingInfo) all landed in API
        // 28. Below that, large chunks of the library degraded to
        // null / inconclusive without giving the consumer real value.
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            // armeabi-v7a (32-bit ARM) is included for compatibility with
            // low-end devices common in EM markets. ART-internals
            // tampering vectors (`integrity.art`) report INCONCLUSIVE on
            // 32-bit because the ArtMethod field-offset table in
            // dicore/art_integrity/offsets.cpp is 64-bit-specific —
            // wiring up 32-bit offsets is a research task per Android
            // version and not yet done. All other detectors
            // (apk / bootloader / attestation / runtime.environment /
            // root / emulator / cloner / runtime DEX-injection) work
            // identically on the third ABI.
            abiFilters += listOf("arm64-v8a", "x86_64", "armeabi-v7a")
        }
        externalNativeBuild {
            cmake {
                cppFlags("-std=c++17", "-fno-exceptions", "-fno-rtti")
                // v2 ECIES tokens are now the DEFAULT: the scan API's backend
                // (ScanVerifier) refuses a v1 token outright rather than accept one
                // on the strength of a baked constant, so a v1 build cannot enroll.
                // -Pdeviceintelligence.tokenV2=0 opts out, and exists only for bisecting the native
                // envelope against a v3 backend — it produces tokens the scan path
                // will reject.
                if ((project.findProperty("deviceintelligence.tokenV2") as String?) != "0") {
                    cppFlags("-DDICORE_TOKEN_V2=1")
                }
                // DIAGNOSTIC builds only: -Pdeviceintelligence.nativeLog=1 keeps DICORE_LOG
                // on in release (RLOG lines under the "dicore" logcat tag).
                // NEVER ship a nativeLog build: logcat becomes a live detector
                // feed and the format strings document the .so.
                if ((project.findProperty("deviceintelligence.nativeLog") as String?) == "1") {
                    cppFlags("-DDICORE_LOG=1")
                }
                // Spec 04 — env-derived-KEK protection of the signer baseline.
                // No stored key: ship only { per-build random seed, ciphertext }; the
                // KEK is re-derived at runtime inside the native core. Input:
                // -Pdeviceintelligence.expectedSigner=<hex>. The crypto lives in build-logic
                // (tech.thessemaj.deviceintelligence.buildtools.BaselineBlob) so this script stays
                // declarative.
                run {
                    val genDir = project.layout.buildDirectory.dir("generated/dicore").get().asFile
                    BaselineBlob.writeHeader(genDir, project.findProperty("deviceintelligence.expectedSigner") as String?)
                    cppFlags("-I${genDir.absolutePath}")
                }
                // Enforcement is UNCONDITIONAL — there is no advisory mode (the
                // same stance as the removed OBSERVE/QUARANTINE: an advisory switch
                // is a loophole an integrator could ship to neuter the RASP). The
                // device-intelligence-lab — detection-only. The enforcement
                // subsystem (watchdog/detonate/kill) has been REMOVED from the
                // source entirely; detectors run and their findings are returned
                // to the caller via the single JNI verdict entry point. No
                // DICORE_*_ENFORCE flags remain.
                arguments(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID_PLATFORM=android-28",
                )
                // Obfuscation: route compile steps through the launcher when resolved.
                obfLauncher?.let { launcher ->
                    arguments(
                        "-DCMAKE_C_COMPILER_LAUNCHER=${launcher.absolutePath}",
                        "-DCMAKE_CXX_COMPILER_LAUNCHER=${launcher.absolutePath}",
                    )
                }
            }
        }

        // Wire VERSION_NAME from gradle.properties through BuildConfig so
        // the runtime can report the exact published coordinate it was
        // built under. TelemetryReport.libraryVersion reads this; the
        // value lines up with the JitPack tag + Maven coordinate, which
        // means a backend correlating reports has a single version
        // identifier across plugin, library, and report payload.
        buildConfigField("String", "LIBRARY_VERSION", "\"$publishVersion\"")

        // Enforcement is unconditional (see the cppFlags above) — native is the
        // sole verdict + killer, there is no advisory/observe mode and no flag that
        // weakens it. A build always crashes the host on a confirmed CRITICAL.
        // NOTE: this means any build (incl. dev/CI/the sample) terminates on a
        // tampered/rooted device; that is intended for a RASP. Genuine devices are
        // never CRITICAL, so they run normally.
        //
        // The native↔Kotlin differential parity gate (run-parity.sh /
        // AttestationParityTest) is RETIRED: it diffed the native parser against
        // KeyDescriptionParser, which no longer exists. Native-parser changes are
        // (the libFuzzer/ASAN harness was removed in the revamp).

        // RASP enforcement is UNCONDITIONAL: a build always crashes on any
        // CRITICAL finding. There is deliberately no enforcement-ceiling flag
        // (no `-Pdi.enforce`) — an observe/quarantine switch would be a loophole
        // an integrator could ship to neuter the RASP, so it does not exist.

        // AndroidJUnitRunner powers the instrumented smoke tests under
        // src/androidTest/. The suite validates `DeviceIntelligence.collect()`
        // produces a structurally well-formed report on real Android
        // (native lib load, every detector ran, summary aggregates
        // consistently). It does NOT assert "no findings" — emulators
        // and dev devices legitimately trip `runtime.emulator` /
        // `integrity.bootloader_unlocked`, and treating those as test
        // failures would mean the suite couldn't run anywhere realistic.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        // We only emit one BuildConfig field (LIBRARY_VERSION). Enabling
        // buildConfig is the cheapest way to get a const into the runtime
        // — far simpler than a generated Kotlin source task for one value.
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            consumerProguardFiles("consumer-rules.pro")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    // AGP-managed virtual devices for instrumented tests. Declarative,
    // reproducible, and runnable in CI without juggling avdmanager /
    // emulator binaries by hand.
    //
    // The three API levels cover the meaningful matrix:
    //   - 28: minSdk floor (the API surface we promise to support).
    //   - 33: Tiramisu, the modal target SDK across Play Store apps.
    //   - 35: latest stable, validates the 16 KB page-size + AGP 8.13
    //         runtime path against current Android.
    //
    // Image-source choice differs per API:
    //   - API 33 / 35 use `aosp-atd` (Android Test Device): headless,
    //     ~250 MB, boots in seconds — purpose-built for CI smoke runs.
    //   - API 28 has no ATD variant (ATD images only ship from API 30
    //     onwards), so it falls back to `aosp` (the full AOSP
    //     `system-images;android-28;default;x86_64` package, ~700 MB,
    //     ~30 sec boot). Functionally equivalent for the smoke suite;
    //     just slower to provision.
    //
    // Run all three locally with:
    //   ./gradlew :deviceintelligence:allDevicesDebugAndroidTest
    // Or a single API level (cheaper in CI) with:
    //   ./gradlew :deviceintelligence:api33DebugAndroidTest
    testOptions {
        managedDevices {
            localDevices {
                // require64Bit pins each device to the 64-bit image
                // variant. Without it, AGP's image-selection heuristic
                // can pick the 32-bit (`x86`) variant on API 28 — both
                // `system-images;android-28;default;x86` and
                // `system-images;android-28;default;x86_64` exist, and
                // the heuristic biases 32-bit on older APIs. That
                // leaves the test APK install failing with
                // INSTALL_FAILED_NO_MATCHING_ABIS, because :deviceintelligence's
                // abiFilters are `[arm64-v8a, x86_64, armeabi-v7a]` —
                // no overlap with a `[x86]`-only device. Explicit on
                // every device for uniform config; effectively a no-op
                // on API 33 / 35 where aosp-atd is x86_64-only anyway.
                create("api28") {
                    device = "Pixel 2"
                    apiLevel = 28
                    systemImageSource = "aosp"
                    require64Bit = true
                }
                create("api33") {
                    device = "Pixel 6"
                    apiLevel = 33
                    systemImageSource = "aosp-atd"
                    require64Bit = true
                }
                create("api35") {
                    device = "Pixel 6"
                    apiLevel = 35
                    systemImageSource = "aosp-atd"
                    require64Bit = true
                }
            }
            groups {
                create("allDevices") {
                    targetDevices.add(localDevices.getByName("api28"))
                    targetDevices.add(localDevices.getByName("api33"))
                    targetDevices.add(localDevices.getByName("api35"))
                }
            }
        }
    }

    // Variant selection + sources/javadoc jars are handled by the
    // vanniktech AndroidSingleVariantLibrary config below.
}

dependencies {
    // Instrumented smoke suite (src/androidTest): exercises the env-bound native
    // path (orchestrate + framework_shim + every detector) on a real device/emulator
    // via the K JNI entry, and decodes the produced tokens in-process with :verifier.
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(project(":verifier"))

    // tech.thessemaj.deviceintelligence.api.DeviceIntelligence exposes the three calls as suspend functions and
    // serialises them on a Mutex. Only Dispatchers/Mutex/withContext are used, all
    // INTERNAL to the facade — no coroutine type appears in a public signature (a
    // suspend function's Continuation is kotlin-stdlib) — so this is
    // `implementation`, not `api`, and consumers are not pinned to this version.
    implementation(libs.kotlinx.coroutines.android)

    // Beyond that facade the core has NO runtime dependencies — detection, verdict, and
    // kill all live in libdicore.so, and the surviving JVM shims use only Android
    // framework APIs + JNI. The old `api(kotlinx-coroutines)` was here to expose
    // the public `suspend collect()` / `Flow observe()` types, but the public API
    // was deleted in the rearchitecture and the lone background dispatch is now a
    // plain daemon Thread. The JVM test trees were removed (the native cores are
    // covered by the libFuzzer harness + on-device verification), so there are no
    // test dependencies either.
}

// Maven Central (Sonatype Central Portal) + signing, via vanniktech.
// Coordinates come from gradle.properties: tech.thessemaj:deviceintelligence.
mavenPublishing {
    configure(
        AndroidSingleVariantLibrary(
            variant = "release",
            sourcesJar = true,
            publishJavadocJar = true,
        )
    )
    publishToMavenCentral(automaticRelease = true)
    // Sign only when a key is supplied (CI). JitPack's keyless
    // publishToMavenLocal must keep working.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }
    coordinates(publishGroup, libraryArtifactId, publishVersion)
    pom {
        name.set("DeviceIntelligence")
        description.set(
            "Android device-intelligence telemetry SDK: hardware-backed " +
                "key attestation, bootloader integrity, root indicators, " +
                "in-process tampering, emulator probe, app-cloner signals " +
                "— emitted as a single deterministic JSON report."
        )
        url.set("https://github.com/iamjosephmj/DeviceIntelligence")
        licenses {
            license {
                name.set("Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)")
                url.set("https://creativecommons.org/licenses/by-nd/4.0/legalcode")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("iamjosephmj")
                name.set("Joseph James")
                url.set("https://github.com/iamjosephmj")
            }
        }
        scm {
            url.set("https://github.com/iamjosephmj/DeviceIntelligence")
            connection.set("scm:git:git://github.com/iamjosephmj/DeviceIntelligence.git")
            developerConnection.set("scm:git:ssh://git@github.com/iamjosephmj/DeviceIntelligence.git")
        }
    }
}

// Keep publishing the AAR to GitHub Packages too (CI only — GITHUB_REPOSITORY
// + GITHUB_TOKEN are set by the runner). vanniktech owns the publications;
// this only adds a second repository target.
publishing {
    repositories {
        System.getenv("GITHUB_REPOSITORY")?.let { gpr ->
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/$gpr")
                credentials {
                    username = System.getenv("GITHUB_ACTOR").orEmpty()
                    password = System.getenv("GITHUB_TOKEN").orEmpty()
                }
            }
        }
    }
}

// JitPack applies `/deps.gradle`, which registers `:deviceintelligence:listDeps` to walk
// configurations for metadata. That can throw ConcurrentModificationException with AGP 8.13 +
// Kotlin when configurations mutate during traversal. Our `jitpack.yml` publishes via
// `publishToMavenLocal`; listing is auxiliary — disable only when `JITPACK=true`.
if (!System.getenv("JITPACK").isNullOrEmpty()) {
    tasks.whenTaskAdded {
        if (name == "listDeps") {
            enabled = false
        }
    }
}

// ---------------------------------------------------------------------------
// signal_ids.gen.h freshness guard.
//
// signals-registry.json is the source of truth for SIG codes; the native emitter
// resolves (detector, kind) -> code through the GENERATED header. Edit the registry,
// forget to regenerate, and the build still succeeds — the finding then serializes as
// INTEL_UNKNOWN at runtime, which the backend cannot resolve. The header calls that
// "a loud signal that the registry is stale", but nothing was listening (issue #12).
//
// The generator embeds `registry-sha256:` (the digest of the registry it read). This
// task recomputes that digest and fails on a mismatch. Deliberately implemented with
// JDK crypto rather than by shelling out to the generator, so the build gains NO
// python dependency — JitPack and CI publish through this path.
val checkSignalRegistryFresh by tasks.registering {
    group = "verification"
    description = "Fails if signal_ids.gen.h is stale w.r.t. signals-registry.json."

    val registry = rootProject.file("tools/registry/signals-registry.json")
    val header = file("src/main/cpp/dicore/orchestrator/signal_ids.gen.h")
    inputs.file(registry)
    inputs.file(header)
    // Declaring an output lets Gradle mark the task UP-TO-DATE instead of rerunning
    // it on every build; the stamp itself is not consumed by anything.
    val stamp = layout.buildDirectory.file("tmp/signal-registry-fresh.txt")
    outputs.file(stamp)

    doLast {
        if (!registry.exists()) throw GradleException("missing ${registry.path}")
        if (!header.exists()) throw GradleException("missing ${header.path}")

        val actual = MessageDigest.getInstance("SHA-256")
            .digest(registry.readBytes())
            .joinToString("") { b -> "%02x".format(b) }

        val recorded = Regex("registry-sha256:\\s*([0-9a-f]{64})")
            .find(header.readText())?.groupValues?.get(1)
            ?: throw GradleException(
                "signal_ids.gen.h has no `registry-sha256:` marker — it predates the " +
                "freshness guard. Regenerate:\n" +
                "    python3 tools/registry/gen-signal-ids.py")

        if (recorded != actual) throw GradleException(
            "signal_ids.gen.h is STALE.\n" +
            "  signals-registry.json sha256 = $actual\n" +
            "  signal_ids.gen.h    recorded = $recorded\n" +
            "The registry changed without regenerating the native lookup table; findings " +
            "for the affected codes would serialize as INTEL_UNKNOWN. Fix with:\n" +
            "    python3 tools/registry/gen-signal-ids.py")

        stamp.get().asFile.apply { parentFile.mkdirs() }.writeText(actual)
    }
}

// ---------------------------------------------------------------------------
// FrameworkShim op-code contract guard.
//
// FrameworkShim.q(op) (Kotlin) <-> fw_q/jvm_asset(op) (framework_shim.cpp) are a
// two-sided literal-int contract with no single source of truth. When they drift,
// native calls an op the `when` no longer handles, gets null back, and every
// up-call degrades FAIL-OPEN — detectors run blind with no error anywhere.
// The scanner (build-logic: tech.thessemaj.deviceintelligence.buildtools.ShimOpContract) fails the
// build when the native side calls an op Kotlin does not handle, same spirit as
// the registry freshness guard above. Pure JDK: no python/shell dependency.
val checkFrameworkShimOps by tasks.registering {
    group = "verification"
    description = "Fails if native calls a FrameworkShim op the Kotlin when() does not handle."

    val shimKt = file("src/main/kotlin/tech/thessemaj/deviceintelligence/internal/FrameworkShim.kt")
    val cppRoot = file("src/main/cpp")
    inputs.file(shimKt)
    inputs.dir(cppRoot)
    val stamp = layout.buildDirectory.file("tmp/framework-shim-ops.txt")
    outputs.file(stamp)

    doLast {
        tech.thessemaj.deviceintelligence.buildtools.ShimOpContract.check(shimKt, cppRoot)
        val r = tech.thessemaj.deviceintelligence.buildtools.ShimOpContract.scan(shimKt, cppRoot)
        stamp.get().asFile.apply { parentFile.mkdirs() }
            .writeText("kotlin=${r.kotlinOps.sorted()} native=${r.nativeOps.sorted()}\n")
    }
}

tasks.named("preBuild") { dependsOn(checkSignalRegistryFresh, checkFrameworkShimOps) }
