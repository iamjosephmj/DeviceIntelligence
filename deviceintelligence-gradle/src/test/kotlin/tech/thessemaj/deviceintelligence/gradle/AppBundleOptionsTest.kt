package tech.thessemaj.deviceintelligence.gradle

import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class AppBundleOptionsTest {
    @Test fun defaultsOffEmpty() {
        val ext = ProjectBuilder.builder().build().objects.newInstance(AppBundleOptions::class.java)
        assertFalse(ext.enabled.getOrElse(false))
        assertEquals(emptySet<String>(), ext.playSigningCertSha256.getOrElse(emptySet()))
    }

    @Test fun helperNormalizes() {
        val ext = ProjectBuilder.builder().build().objects.newInstance(AppBundleOptions::class.java)
        ext.playSigningCertSha256("AB:CD:EF")
        assertEquals(setOf("abcdef"), ext.playSigningCertSha256.get())
    }
}
