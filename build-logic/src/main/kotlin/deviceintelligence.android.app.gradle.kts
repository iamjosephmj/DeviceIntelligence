import org.jetbrains.kotlin.gradle.dsl.JvmTarget

/**
 * Android application convention (:samples:minimal, :corpus:red-team:lsposed-tester):
 * AGP + Kotlin/Android, compileSdk 36, source + bytecode pinned to 17.
 * Module-specific config (applicationId, minSdk, buildTypes, signing) stays in
 * the module's own build file; anything it sets overrides these defaults.
 */
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}
