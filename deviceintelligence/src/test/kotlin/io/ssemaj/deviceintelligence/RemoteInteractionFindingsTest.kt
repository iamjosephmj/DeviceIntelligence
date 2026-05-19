package io.ssemaj.deviceintelligence

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Locks the snapshot data shape exposed on
 * [SessionFindings.remoteInteraction]. Phase 1 ships only the
 * default/empty shape; subsequent phases populate fields.
 */
class RemoteInteractionFindingsTest {

    @Test
    fun `EMPTY snapshot has all collections empty and INFO highest severity`() {
        val empty = RemoteInteractionFindings.EMPTY
        assertTrue(empty.enabledA11yServices.isEmpty())
        assertTrue(empty.remoteControlPackages.isEmpty())
        assertTrue(empty.capabilityProfileMatches.isEmpty())
        assertTrue(empty.externalInputDevices.isEmpty())
        assertTrue(empty.overlayCapablePackages.isEmpty())
        assertTrue(empty.notificationListenerPackages.isEmpty())
        assertTrue(empty.activeDeviceAdmins.isEmpty())
        assertNull(empty.activeVpnOwnerPackage)
        assertFalse(empty.screenCaptureActive)
        assertNull(empty.screenCaptureActiveSince)
        assertTrue(empty.eventCounts.isEmpty())
        assertEquals(InteractionSeverity.INFO, empty.highestSeverityObserved)
    }

    @Test
    fun `EMPTY snapshot is a single shared instance`() {
        // Hot-path callers (every SessionFindings rollup) read EMPTY.
        // Allocating on every read would be wasteful.
        assertTrue(RemoteInteractionFindings.EMPTY === RemoteInteractionFindings.EMPTY)
    }
}
