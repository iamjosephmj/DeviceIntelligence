plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// Minimal LSPosed (Xposed) module used purely to verify
// DeviceIntelligence's anti-hooking detectors (G5 StackGuard /
// G6 StackWatchdog). It hooks the public DeviceIntelligence API
// surface so that XposedBridge / LSPHooker frames appear on the
// stack of `StackGuard.verify()`, which the runtime then lifts
// into `stack_foreign_frame` findings.
//
// This module is NOT shipped to consumers and intentionally has
// no dependency on the DeviceIntelligence library. It is
// installed alongside the sample app on a rooted, LSPosed-
// enabled device, then activated and scoped to
// `io.ssemaj.sample` via the LSPosed Manager UI.
android {
    namespace = "io.ssemaj.lspmodule"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.ssemaj.lspmodule"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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

dependencies {
    // CompileOnly: the LSPosed framework supplies the real
    // implementation at runtime. If this were `implementation`
    // the stub classes would be packaged into the dex and shadow
    // the framework's classes, breaking every hook.
    compileOnly(project(":samples:xposed-api-stubs"))
}
