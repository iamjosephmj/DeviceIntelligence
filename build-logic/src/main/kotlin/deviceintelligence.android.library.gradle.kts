import org.jetbrains.kotlin.gradle.dsl.JvmTarget

/**
 * Android library convention (:deviceintelligence): AGP + Kotlin/Android, compileSdk 36,
 * source + bytecode pinned to 17. Module-specific config (namespace, minSdk,
 * NDK, publishing) stays in the module's own build file.
 */
plugins {
    id("com.android.library")
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
