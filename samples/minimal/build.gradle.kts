plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    id("io.ssemaj.deviceintelligence") version "0.2.0"
}

android {
    namespace = "io.ssemaj.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.ssemaj.sample"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.2.0"
    }

    // Sample-only: reuse the SDK-installed debug keystore for release
    // so the DeviceIntelligence Gradle plugin (which needs a fully resolved
    // signingConfig per buildType) can bake a fingerprint into the
    // release APK and we can demo integrity.apk in release mode. A real consumer
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
    // Published JitPack runtime (same version as the plugin). Without this,
    // the plugin would substitute the in-tree :deviceintelligence project and
    // the sample would not match what external apps resolve from JitPack.
    disableAutoRuntimeDependency.set(true)
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

// Runtime AAR comes from JitPack (same version as the plugin) so this sample
// matches external consumer resolution. The library module remains in the root
// build for `./gradlew :deviceintelligence:*`; use `disableAutoRuntimeDependency`
// here to avoid the plugin's in-tree :deviceintelligence substitution.
dependencies {
    implementation("com.github.iamjosephmj.DeviceIntelligence:deviceintelligence:0.2.0")
}

