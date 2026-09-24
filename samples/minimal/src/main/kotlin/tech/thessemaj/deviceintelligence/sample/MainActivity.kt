package tech.thessemaj.deviceintelligence.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import tech.thessemaj.deviceintelligence.sample.navigation.SampleNavHost
import tech.thessemaj.deviceintelligence.sample.ui.component.Plumage
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors
import tech.thessemaj.deviceintelligence.sample.ui.theme.DiSampleTheme
import dagger.hilt.android.AndroidEntryPoint

/**
 * Self-contained test host for device-intelligence-lab.
 *
 * For DEMO/TESTING this app plays BOTH sides of the scan flow:
 *  - DEVICE: [tech.thessemaj.deviceintelligence.api.DeviceIntelligence.initialize] validates the licence blob locally,
 *    `setSession` takes the app's own session id, and `scan` produces one encrypted token.
 *  - BACKEND: the bundled [tech.thessemaj.deviceintelligence.verifier.ScanVerifier] — the very code a real
 *    server runs — decrypts and verifies it IN-PROCESS and renders the verdict.
 *
 * The FIRST scan of a cold start is the expensive one: it attests a hardware key
 * bound to the session id and carries the certificate chain. Every later scan
 * signs with that key and is cheap.
 *
 * In production the verify half runs server-side, and the X25519 private key
 * shipped in `res/raw` lives there, not in the APK; here both are folded in so the
 * whole loop closes on-device with no external tooling.
 *
 * The flow itself lives in `domain/usecase`, the SDK calls in `data`, and every
 * screen in `ui`. This class only hosts them.
 */
@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            DiSampleTheme {
                // One floor for the whole app; screens slide across it.
                Box(Modifier.fillMaxSize().background(IntelColors.Background)) {
                    Plumage()
                    SampleNavHost(Modifier.fillMaxSize())
                }
            }
        }
    }
}
