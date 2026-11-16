plugins {
    id("deviceintelligence.android.app")   // convention: AGP + Kotlin/Android, compileSdk 36, JVM 17
    // The Compose compiler moved into the Kotlin plugin from 2.0; it is versioned
    // with `kotlin`, never separately.
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
    alias(libs.plugins.deviceintelligence)
}

android {
    namespace = "tech.thessemaj.deviceintelligence.sample"

    defaultConfig {
        applicationId = "tech.thessemaj.deviceintelligence.sample"
        minSdk = 28
        targetSdk = 36
        versionCode = 6
        versionName = "1.5.0"

        // Mirror dicore's shipped ABIs at the APP level. Without this the APK is
        // "fat": androidx dependencies (e.g. graphics-path) ship every ABI
        // including 32-bit x86, so on an x86 emulator (abilist x86,armeabi-v7a)
        // PackageManager picks x86 as the PRIMARY ABI — and then
        // System.loadLibrary("dicore") fails, because dicore ships no x86 lib.
        // The symptom is misleading: initialize() reports licence failure (the
        // shim never registers), not a load error. Pinning the filters makes
        // such devices install the armeabi-v7a build under ARM translation
        // instead — where INTEL_0027 translated_environment fires by design.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    // Sample-only: reuse the SDK-installed debug keystore for release
    // so the DeviceIntelligence Gradle plugin (which needs a fully resolved
    // signingConfig per buildType) can bake a fingerprint into the
    // release APK and we can demo integrity.apk in release mode. A real consumer
    // would point this at a production keystore.
    lint {
        // PackagedPrivateKey fires on res/raw/dev_backend_priv.pem, and it is RIGHT:
        // that file is an X25519 private key and it really is inside the APK.
        //
        // It is there on purpose. This sample is its own backend — MainActivity reads
        // the key to verify the token it just produced — so the demo closes on-device
        // with nothing to deploy. The key is TEST-ONLY: a real integration keeps its
        // private half on the server and mints its own pair with `deviceintelligenceGenerateKey`.
        //
        // Scoped to this one check in this one sample module, never in :deviceintelligence. If this
        // repository is ever made public, this key is published with it — rotate it
        // and move it out of res/raw before that happens.
        disable += "PackagedPrivateKey"
    }

    signingConfigs {
        create("releaseDebugKey") {
            storeFile = rootProject.file(
                System.getenv("DI_RELEASE_KEYSTORE")
                    ?: "${System.getProperty("user.home")}/.android/debug.keystore",
            )
            storePassword = System.getenv("DI_RELEASE_KEYSTORE_PASSWORD") ?: "android"
            keyAlias = System.getenv("DI_RELEASE_KEY_ALIAS") ?: "androiddebugkey"
            keyPassword = System.getenv("DI_RELEASE_KEY_PASSWORD") ?: "android"
        }
    }

    buildTypes {
        release {
            // R8 on for release: shrinks + obfuscates the class/method/package
            // consumer-rules.pro (auto-applied) keeps the JNI surface, the
            // reflection-bound key assembler and the init provider.
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("releaseDebugKey")
        }
    }

    buildFeatures {
        compose = true
        // BuildConfig.DEBUG guards the debug-only chaos hook (and its button);
        // AGP omits the class unless it is asked for.
        buildConfig = true
    }

}

deviceintelligence {
    verbose.set(true)
}

// No `dependencies { implementation("...:deviceintelligence:...") }` here.
// The DeviceIntelligence Gradle plugin auto-wires the runtime AAR. In this
// repo `:deviceintelligence` is included in the root build, so the plugin
// substitutes `project(":deviceintelligence")` (fast in-tree dev loop). For
// an external consumer with no `:deviceintelligence` module, the plugin
// auto-resolves the matching JitPack AAR instead. Either way the consumer
// applies the plugin and writes nothing else — see README "Install".

// TESTING ONLY: bundle the backend verifier (pure Kotlin/JVM, zero-dep) INTO the
// sample so the app can play BOTH roles — device (K.initialize/K.challenge produce
// tokens) AND backend (EnrollVerifier/TokenVerifier verify them in-process, issue
// the session, decide the verdict). In production the verify happens server-side;
// this closes the loop on-device for demo/testing. The :verifier module uses only
// JDK crypto (available on Android API 28+) and bundles its resources
// (signals-registry.json, pinned-roots.txt) which merge into the APK.
dependencies {
    implementation(project(":verifier-kotlin"))

    // --- Compose UI ---
    // The BOM pins every compose artifact below to one tested set.
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.navigation.compose)
    // --- scroll feel ---
    implementation(libs.flinger)
    implementation(libs.squishy)

    // --- DI ---
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.androidx.hilt.navigation.compose)

    // --- unit tests (JVM) ---
    testImplementation(libs.junit)
    // tech.thessemaj.deviceintelligence.api.DeviceIntelligence exposes the SDK as suspend functions. :deviceintelligence depends
    // on coroutines with `implementation`, so a consumer that calls the facade
    // declares it too.
    implementation(libs.kotlinx.coroutines.android)
}
