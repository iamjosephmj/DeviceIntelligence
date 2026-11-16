package tech.thessemaj.deviceintelligence.sample.navigation

/**
 * The screens this app has. Two levels: the scan screen, and one screen per area
 * of the evidence.
 *
 * These carry no arguments — the scan result lives in the shared [tech.thessemaj.deviceintelligence.sample.ui.scan.ScanViewModel]
 * rather than being serialised through the back stack, because a `ScanResult` is a
 * large graph and passing it as a route argument would mean flattening it to JSON
 * on every navigation.
 */
enum class Destination(val route: String) {
    Scan("scan"),
    Attestation("attestation"),
    Checks("checks"),
    Signals("signals"),
    Fingerprint("fingerprint"),
    SessionFacts("session"),
}
