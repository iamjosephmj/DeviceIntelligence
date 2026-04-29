plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("io.ssemaj.deviceintelligence")
}

android {
    namespace = "io.ssemaj.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.ssemaj.sample"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1"
    }

    // Sample-only: reuse the SDK-installed debug keystore for release
    // so the DeviceIntelligence Gradle plugin (which needs a fully resolved
    // signingConfig per buildType) can bake a fingerprint into the
    // release APK and we can demo F10 in release mode. A real consumer
    // would point this at a production keystore.
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
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("releaseDebugKey")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

deviceintelligence {
    verbose.set(true)
    // Opt in to VPN detection so DeviceContext.vpnActive populates
    // (true / false instead of null). The plugin injects
    // ACCESS_NETWORK_STATE into the sample's merged manifest;
    // apps that skip this still build and run, just with
    // vpnActive = null in the report.
    enableVpnDetection.set(true)
    // Opt in to biometrics-enrollment detection so
    // DeviceContext.biometricsEnrolled populates. Injects
    // USE_BIOMETRIC (normal-protection, no runtime prompt). Same
    // graceful-degradation story as enableVpnDetection.
    enableBiometricsDetection.set(true)
}

// Notice the absence of `dependencies { implementation(project(":deviceintelligence")) }` here.
// The DeviceIntelligence Gradle plugin's apply() auto-adds the runtime AAR for us — and
// because :deviceintelligence is a sibling project of this sample (in-tree dev loop), the
// plugin substitutes a project-dependency rather than the published JitPack coordinate. This
// is the single-line-integration story that matches what real consumers get from JitPack;
// it just resolves locally during this repo's own dev loop.
