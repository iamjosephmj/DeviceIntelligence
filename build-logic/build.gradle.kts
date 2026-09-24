plugins {
    `kotlin-dsl`
}

dependencies {
    // `implementation`, not `compileOnly`: precompiled script plugins resolve
    // the plugin ids in their `plugins {}` block against this configuration.
    implementation(libs.android.gradlePlugin)
    implementation(libs.kotlin.gradlePlugin)
}
