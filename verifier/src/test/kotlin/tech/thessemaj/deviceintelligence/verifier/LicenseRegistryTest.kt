package tech.thessemaj.deviceintelligence.verifier

import org.junit.Assert.*
import org.junit.Test

class LicenseRegistryTest {
    private val reg = StaticLicenseRegistry(mapOf("com.example.app" to setOf("aa".repeat(32))))

    @Test fun matching_package_and_digest_is_licensed() {
        assertTrue(reg.isLicensed("com.example.app", "aa".repeat(32)))
    }

    @Test fun right_package_wrong_digest_is_not_licensed() {
        assertFalse("a repackager keeps the name but not the signing key",
            reg.isLicensed("com.example.app", "bb".repeat(32)))
    }

    @Test fun unknown_package_is_not_licensed() {
        assertFalse(reg.isLicensed("com.other.app", "aa".repeat(32)))
    }

    @Test fun digest_comparison_ignores_case() {
        assertTrue("digests arrive from two sources with no case guarantee",
            reg.isLicensed("com.example.app", "AA".repeat(32)))
    }

    @Test fun the_open_registry_licenses_anything() {
        assertTrue(OpenLicenseRegistry.isLicensed("anything", "00"))
    }
}
