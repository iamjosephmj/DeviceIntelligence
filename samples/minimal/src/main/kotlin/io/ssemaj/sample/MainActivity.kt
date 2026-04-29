package io.ssemaj.sample

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.DeviceContext
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.DeviceIntelligence
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.TelemetryReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Telemetry viewer for the DeviceIntelligence sample.
 *
 * DeviceIntelligence is a telemetry layer — it does not block, lock,
 * or crash. The sample reflects that: there is no "verdict". Instead
 * the screen presents the latest [TelemetryReport] as a stack of
 * cards (Hero, Actions, Device, App, Findings, Detectors, JSON) and
 * the user can:
 *
 *  - **Re-collect**: re-run every detector and re-render.
 *  - **Copy JSON**: copy the full JSON to the clipboard, exactly as
 *    a backend would receive it.
 */
class MainActivity : Activity() {

    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var ui: Ui

    private lateinit var heroContainer: LinearLayout
    private lateinit var heroTitle: TextView
    private lateinit var heroSubtitle: TextView
    private lateinit var heroMeta: TextView
    private lateinit var heroChips: FlowLayout

    private lateinit var deviceCardBody: LinearLayout
    private lateinit var appCardBody: LinearLayout

    private lateinit var findingsCard: LinearLayout
    private lateinit var findingsBody: LinearLayout
    private lateinit var findingsTitleRow: LinearLayout

    private lateinit var detectorsBody: LinearLayout
    private lateinit var detectorsTitleRow: LinearLayout

    private lateinit var jsonCardBody: LinearLayout
    private lateinit var jsonView: TextView
    private lateinit var jsonToggleBtn: Button
    private var jsonExpanded: Boolean = false

    @Volatile
    private var lastReport: TelemetryReport? = null
    @Volatile
    private var lastJson: String = ""

    private val tsFmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { requestWindowFeature(Window.FEATURE_NO_TITLE) }
        actionBar?.hide()
        ui = Ui.forContext(this)
        window.statusBarColor = ui.palette.pageBg
        window.navigationBarColor = ui.palette.pageBg

        setContentView(buildScaffold())
        Log.i(TAG, "activity created")

        // Run once before paint so the first frame already has data.
        runCollect(initial = true)
    }

    override fun onDestroy() {
        super.onDestroy()
        mainHandler.removeCallbacksAndMessages(null)
    }

    // ---- scaffold ----------------------------------------------------------

    private fun buildScaffold(): ScrollView {
        val padH = Ui.dp(this, 16)
        val padV = Ui.dp(this, 20)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padH, padV, padH, padV)
            setBackgroundColor(ui.palette.pageBg)
            fitsSystemWindows = true
        }

        // ---- hero ----
        heroContainer = ui.heroBanner(this).also { root.addView(it) }
        heroTitle = TextView(this).apply {
            textSize = 12f
            setTextColor(ui.palette.subtitle)
            text = "DEVICEINTELLIGENCE"
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            letterSpacing = 0.12f
        }
        heroSubtitle = TextView(this).apply {
            textSize = 32f
            setTextColor(ui.palette.title)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            text = "collecting…"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 6) }
        }
        heroMeta = TextView(this).apply {
            textSize = 12.5f
            setTextColor(ui.palette.subtitle)
            text = ""
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 4) }
        }
        heroChips = ui.badgeRow(this, topMargin = 14)
        heroContainer.addView(heroTitle)
        heroContainer.addView(heroSubtitle)
        heroContainer.addView(heroMeta)
        heroContainer.addView(heroChips)

        // ---- actions ----
        val actionsCard = ui.card(this).also { root.addView(it) }
        actionsCard.addView(ui.titleRow(this, "Actions"))
        actionsCard.addView(
            ui.subtitle(
                this,
                "Re-collect re-runs every detector. Copy JSON puts the full " +
                    "telemetry blob (exactly what a backend would receive) on " +
                    "the clipboard.",
            ),
        )
        val actionsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 12) }
        }
        actionsRow.addView(makeButton("Re-collect", Ui.Tone.INFO) { runCollect(initial = false) })
        actionsRow.addView(makeButton("Copy JSON", Ui.Tone.NEUTRAL) { copyJsonToClipboard() })
        actionsCard.addView(actionsRow)

        // ---- device snapshot ----
        val deviceCard = ui.card(this).also { root.addView(it) }
        deviceCard.addView(ui.titleRow(this, "Device"))
        deviceCard.addView(
            ui.subtitle(this, "Hardware + OS facts. Used for cohorting and emulator heuristics."),
        )
        deviceCardBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        deviceCard.addView(deviceCardBody)

        // ---- app snapshot ----
        val appCard = ui.card(this).also { root.addView(it) }
        appCard.addView(ui.titleRow(this, "App"))
        appCard.addView(ui.subtitle(this, "Identity, install attribution, and signer chain."))
        appCardBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        appCard.addView(appCardBody)

        // ---- findings ----
        findingsCard = ui.card(this).also { root.addView(it) }
        findingsTitleRow = ui.titleRow(this, "Findings", listOf(ui.badge(this, "0", Ui.Tone.NEUTRAL)))
        findingsCard.addView(findingsTitleRow)
        findingsCard.addView(
            ui.subtitle(this, "Each row is one Finding. Severity is advisory; backends decide policy."),
        )
        findingsBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        findingsCard.addView(findingsBody)

        // ---- detectors ----
        val detectorsCard = ui.card(this).also { root.addView(it) }
        detectorsTitleRow = ui.titleRow(this, "Detectors", listOf(ui.badge(this, "0", Ui.Tone.NEUTRAL)))
        detectorsCard.addView(detectorsTitleRow)
        detectorsCard.addView(
            ui.subtitle(this, "One row per registered detector with status, duration and finding count."),
        )
        detectorsBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        detectorsCard.addView(detectorsBody)

        // ---- json (collapsible) ----
        val jsonCard = ui.card(this).also { root.addView(it) }
        jsonToggleBtn = makeButton("Show", Ui.Tone.NEUTRAL) { toggleJson() }.apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        jsonCard.addView(ui.titleRow(this, "Telemetry JSON", listOf(jsonToggleBtn)))
        jsonCard.addView(
            ui.subtitle(
                this,
                "Exactly the bytes a backend would receive from DeviceIntelligence.collectJson(context).",
            ),
        )
        jsonCardBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        jsonView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextColor(ui.palette.mono)
            setTextIsSelectable(true)
            setLineSpacing(0f, 1.2f)
            text = "(collecting…)"
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
        }
        jsonCardBody.addView(jsonView)
        jsonCard.addView(jsonCardBody)

        return ScrollView(this).apply {
            setBackgroundColor(ui.palette.pageBg)
            fitsSystemWindows = true
            isScrollbarFadingEnabled = true
            addView(
                root,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
    }

    // ---- collect & render --------------------------------------------------

    private fun runCollect(initial: Boolean) {
        Thread({
            val report = try {
                DeviceIntelligence.collect(this)
            } catch (t: Throwable) {
                Log.e(TAG, "DeviceIntelligence.collect threw", t)
                null
            }
            mainHandler.post {
                if (report == null) {
                    jsonView.text = "(collect failed — see logcat)"
                    Log.w(TAG, "collect failed")
                    return@post
                }
                lastReport = report
                lastJson = report.toJson()
                renderHero(report)
                renderDevice(report.device)
                renderApp(report.app)
                renderFindings(report)
                renderDetectors(report.detectors)
                jsonView.text = lastJson
                val findingCount = report.summary.totalFindings
                val verb = if (initial) "initial collect" else "recollect"
                Log.i(TAG, "$verb done: $findingCount finding(s) in ${report.collectionDurationMs}ms")
                Log.i(JSON_TAG, lastJson)
            }
        }, "sample-collect").apply { isDaemon = true }.start()
    }

    // ---- rendering helpers -------------------------------------------------

    private fun renderHero(report: TelemetryReport) {
        val total = report.summary.totalFindings
        val critical = report.summary.findingsBySeverity[Severity.CRITICAL] ?: 0
        val high = report.summary.findingsBySeverity[Severity.HIGH] ?: 0

        // Tone is informational only — DeviceIntelligence is telemetry,
        // not policy. Pick a tone for legibility (red if anything
        // CRITICAL, amber if anything HIGH, gray otherwise) but the
        // JSON is the source of truth.
        val tone = when {
            critical > 0 -> Ui.Tone.BAD
            high > 0 -> Ui.Tone.WARN
            total > 0 -> Ui.Tone.INFO
            else -> Ui.Tone.OK
        }
        ui.tintHero(heroContainer, tone)

        heroSubtitle.text = when {
            total == 0 -> "All clear"
            total == 1 -> "1 finding"
            else -> "$total findings"
        }
        heroMeta.text = buildString {
            append(report.device.manufacturer)
            append(' ')
            append(report.device.model)
            append(" · API ")
            append(report.device.sdkInt)
            append(" · ")
            append(report.detectors.size)
            append(" detectors · ")
            append(report.collectionDurationMs)
            append(" ms · v")
            append(report.libraryVersion)
        }

        heroChips.removeAllViews()
        val sev = report.summary.findingsBySeverity
        addHeroChip("critical", sev[Severity.CRITICAL] ?: 0, Ui.Tone.BAD)
        addHeroChip("high", sev[Severity.HIGH] ?: 0, Ui.Tone.WARN)
        addHeroChip("medium", sev[Severity.MEDIUM] ?: 0, Ui.Tone.INFO)
        addHeroChip("low", sev[Severity.LOW] ?: 0, Ui.Tone.NEUTRAL)
        if (report.summary.detectorsInconclusive.isNotEmpty()) {
            addHeroChip(
                "inconclusive",
                report.summary.detectorsInconclusive.size,
                Ui.Tone.NEUTRAL,
            )
        }
        if (report.summary.detectorsErrored.isNotEmpty()) {
            addHeroChip("errors", report.summary.detectorsErrored.size, Ui.Tone.BAD)
        }
    }

    private fun addHeroChip(label: String, count: Int, tone: Ui.Tone) {
        ui.addToBadgeRow(heroChips, ui.badge(this, "$label · $count", tone))
    }

    private fun renderDevice(device: DeviceContext) {
        deviceCardBody.removeAllViews()
        deviceCardBody.addView(ui.kv(this, "manufacturer", device.manufacturer))
        deviceCardBody.addView(ui.kv(this, "model", device.model))
        deviceCardBody.addView(ui.kv(this, "android", "API ${device.sdkInt}"))
        deviceCardBody.addView(ui.kv(this, "abi", device.abi))
        device.totalRamMb?.let { deviceCardBody.addView(ui.kv(this, "ram", "${it} MiB")) }
        device.cpuCores?.let { deviceCardBody.addView(ui.kv(this, "cpu cores", it.toString())) }
        if (device.screenResolution != null || device.screenDensityDpi != null) {
            val text = buildString {
                device.screenResolution?.let { append(it) }
                if (device.screenDensityDpi != null) {
                    if (isNotEmpty()) append("  ")
                    append("${device.screenDensityDpi}dpi")
                }
            }
            deviceCardBody.addView(ui.kv(this, "screen", text))
        }
        device.sensorCount?.let { deviceCardBody.addView(ui.kv(this, "sensors", it.toString())) }
        device.bootCount?.let { deviceCardBody.addView(ui.kv(this, "boot count", it.toString())) }
        deviceCardBody.addView(ui.kv(this, "fingerprint", truncate(device.fingerprint, 56)))

        val badges = ui.badgeRow(this, topMargin = 12)
        device.hasFingerprintHw?.let {
            ui.addToBadgeRow(
                badges,
                ui.badge(this, if (it) "fingerprint hw" else "no fingerprint hw",
                    if (it) Ui.Tone.OK else Ui.Tone.NEUTRAL),
            )
        }
        device.hasTelephonyHw?.let {
            ui.addToBadgeRow(
                badges,
                ui.badge(this, if (it) "telephony" else "no telephony",
                    if (it) Ui.Tone.OK else Ui.Tone.NEUTRAL),
            )
        }
        device.vpnActive?.let {
            ui.addToBadgeRow(
                badges,
                ui.badge(this, if (it) "vpn active" else "no vpn",
                    if (it) Ui.Tone.WARN else Ui.Tone.NEUTRAL),
            )
        }
        device.strongboxAvailable?.let {
            ui.addToBadgeRow(
                badges,
                ui.badge(this, if (it) "strongbox hw" else "no strongbox",
                    if (it) Ui.Tone.OK else Ui.Tone.NEUTRAL),
            )
        }
        if (badges.childCount > 0) deviceCardBody.addView(badges)
    }

    private fun renderApp(app: AppContext) {
        appCardBody.removeAllViews()
        appCardBody.addView(ui.kv(this, "package", app.packageName))
        appCardBody.addView(ui.kv(this, "variant", app.buildVariant))
        appCardBody.addView(ui.kv(this, "plugin", app.libraryPluginVersion))
        appCardBody.addView(ui.kv(this, "target sdk", app.targetSdkVersion?.toString()))
        app.installSource?.let {
            appCardBody.addView(ui.kv(this, "install src", it.installingPackage))
            it.initiatingPackage?.takeIf { p -> p != it.installingPackage }
                ?.let { p -> appCardBody.addView(ui.kv(this, "initiating", p)) }
            it.originatingPackage?.takeIf { p -> p != it.installingPackage }
                ?.let { p -> appCardBody.addView(ui.kv(this, "originating", p)) }
        } ?: app.installerPackage?.let {
            appCardBody.addView(ui.kv(this, "installer", it))
        }
        app.firstInstallEpochMs?.let {
            appCardBody.addView(ui.kv(this, "installed", tsFmt.format(Date(it))))
        }
        app.lastUpdateEpochMs?.let {
            appCardBody.addView(ui.kv(this, "updated", tsFmt.format(Date(it))))
        }
        if (app.signerCertSha256.isNotEmpty()) {
            appCardBody.addView(ui.kv(this, "signer sha256", truncate(app.signerCertSha256[0], 22)))
            if (app.signerCertSha256.size > 1) {
                appCardBody.addView(
                    ui.kv(this, "signer count", app.signerCertSha256.size.toString()),
                )
            }
        }
        app.attestation?.let { att ->
            val badges = ui.badgeRow(this, topMargin = 12)
            att.attestationSecurityLevel?.let {
                val tone = when (it) {
                    "StrongBox" -> Ui.Tone.OK
                    "TrustedEnvironment" -> Ui.Tone.OK
                    "Software" -> Ui.Tone.WARN
                    else -> Ui.Tone.NEUTRAL
                }
                ui.addToBadgeRow(badges, ui.badge(this, "tee: $it", tone))
            }
            att.softwareBacked?.let { soft ->
                if (soft) {
                    ui.addToBadgeRow(
                        badges,
                        ui.badge(this, "software-backed keymint", Ui.Tone.WARN),
                    )
                }
            }
            att.verifiedBootState?.let {
                val tone = when (it) {
                    "Verified" -> Ui.Tone.OK
                    "SelfSigned" -> Ui.Tone.WARN
                    else -> Ui.Tone.BAD
                }
                ui.addToBadgeRow(badges, ui.badge(this, "vb: $it", tone))
            }
            att.deviceLocked?.let {
                ui.addToBadgeRow(
                    badges,
                    ui.badge(this, if (it) "bootloader locked" else "bootloader unlocked",
                        if (it) Ui.Tone.OK else Ui.Tone.BAD),
                )
            }
            att.verdictDeviceRecognition?.let { verdict ->
                // The verdict is a comma-separated list of Play-Integrity-API
                // tokens (e.g. "MEETS_DEVICE_INTEGRITY,MEETS_STRONG_INTEGRITY").
                // Render each token as its own chip so a long combined value
                // doesn't end up as one un-wrappable horizontal pill.
                verdict.split(',')
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .forEach { token ->
                        val tone = when {
                            token.contains("STRONG_INTEGRITY") -> Ui.Tone.OK
                            token.contains("DEVICE_INTEGRITY") -> Ui.Tone.OK
                            token.contains("BASIC_INTEGRITY") -> Ui.Tone.WARN
                            else -> Ui.Tone.BAD
                        }
                        ui.addToBadgeRow(badges, ui.badge(this, token.lowercase(), tone))
                    }
            }
            if (badges.childCount > 0) appCardBody.addView(badges)
        }
    }

    private fun renderFindings(report: TelemetryReport) {
        findingsBody.removeAllViews()
        val findings = report.detectors.flatMap { d -> d.findings.map { d.id to it } }
        replaceTitleAccessory(
            findingsTitleRow,
            ui.badge(
                this,
                findings.size.toString(),
                if (findings.isEmpty()) Ui.Tone.OK else Ui.Tone.WARN,
            ),
        )
        if (findings.isEmpty()) {
            findingsBody.addView(
                TextView(this).apply {
                    text = "No findings on this device. The JSON below is what your backend would store."
                    textSize = 12.5f
                    setTextColor(ui.palette.subtitle)
                    setLineSpacing(0f, 1.15f)
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = Ui.dp(this@MainActivity, 10) }
                },
            )
            return
        }
        for ((detectorId, finding) in findings) {
            findingsBody.addView(buildFindingRow(detectorId, finding))
        }
    }

    private fun buildFindingRow(detectorId: String, finding: Finding): View {
        val tone = severityTone(finding.severity)
        val subjectLabel = listOfNotNull(detectorId, finding.subject?.takeIf { it.isNotBlank() })
            .joinToString(" · ")
        return ui.findingRow(
            context = this,
            severityLabel = severityShort(finding.severity),
            tone = tone,
            kind = finding.kind,
            subject = subjectLabel,
            message = finding.message,
        )
    }

    private fun severityShort(s: Severity): String = when (s) {
        Severity.CRITICAL -> "CRIT"
        Severity.HIGH -> "HIGH"
        Severity.MEDIUM -> "MED"
        Severity.LOW -> "LOW"
    }

    private fun renderDetectors(detectors: List<DetectorReport>) {
        detectorsBody.removeAllViews()
        replaceTitleAccessory(
            detectorsTitleRow,
            ui.badge(this, detectors.size.toString(), Ui.Tone.NEUTRAL),
        )
        for (det in detectors) {
            val (label, tone) = detectorStatusBadge(det)
            val right = "${det.durationMs}ms · ${det.findings.size} fnd"
            detectorsBody.addView(
                ui.detectorRow(
                    context = this,
                    id = det.id,
                    statusLabel = label,
                    statusTone = tone,
                    rightLabel = right,
                ),
            )
        }
    }

    private fun detectorStatusBadge(det: DetectorReport): Pair<String, Ui.Tone> = when (det.status) {
        DetectorStatus.OK -> when {
            det.findings.any { it.severity == Severity.CRITICAL } -> "ok" to Ui.Tone.BAD
            det.findings.any { it.severity == Severity.HIGH } -> "ok" to Ui.Tone.WARN
            det.findings.isNotEmpty() -> "ok" to Ui.Tone.INFO
            else -> "ok" to Ui.Tone.OK
        }
        DetectorStatus.INCONCLUSIVE -> "inconclusive" to Ui.Tone.NEUTRAL
        DetectorStatus.ERROR -> "error" to Ui.Tone.BAD
    }

    private fun severityTone(s: Severity): Ui.Tone = when (s) {
        Severity.CRITICAL -> Ui.Tone.BAD
        Severity.HIGH -> Ui.Tone.WARN
        Severity.MEDIUM -> Ui.Tone.INFO
        Severity.LOW -> Ui.Tone.NEUTRAL
    }

    /**
     * Replace the right-most accessory of a [titleRow]-built view
     * with [newAccessory]. Used to keep counts in sync without
     * rebuilding the whole title row every collect.
     */
    private fun replaceTitleAccessory(titleRow: LinearLayout, newAccessory: View) {
        if (titleRow.childCount < 2) return
        titleRow.removeViewAt(titleRow.childCount - 1)
        val lp = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        )
        newAccessory.layoutParams = lp
        titleRow.addView(newAccessory)
    }

    // ---- actions -----------------------------------------------------------

    private fun toggleJson() {
        jsonExpanded = !jsonExpanded
        jsonCardBody.visibility = if (jsonExpanded) View.VISIBLE else View.GONE
        jsonToggleBtn.text = if (jsonExpanded) "Hide" else "Show"
    }

    private fun copyJsonToClipboard() {
        val json = lastJson
        if (json.isEmpty()) {
            toast("Nothing collected yet")
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("DeviceIntelligence telemetry JSON", json))
        toast("JSON copied (${json.length} chars)")
        Log.i(TAG, "copied JSON to clipboard (${json.length} chars)")
    }

    // ---- helpers -----------------------------------------------------------

    private fun makeButton(label: String, tone: Ui.Tone, onClick: () -> Unit): Button {
        val (fg, bg) = when (tone) {
            Ui.Tone.OK -> ui.palette.toneOk
            Ui.Tone.BAD -> ui.palette.toneBad
            Ui.Tone.WARN -> ui.palette.toneWarn
            Ui.Tone.INFO -> ui.palette.toneInfo
            Ui.Tone.NEUTRAL -> ui.palette.toneNeutral
        }
        val padH = Ui.dp(this, 14)
        val padV = Ui.dp(this, 8)
        val drawable = GradientDrawable().apply {
            setColor(bg)
            cornerRadius = Ui.dp(this@MainActivity, 12).toFloat()
        }
        return Button(this).apply {
            text = label
            textSize = 12f
            setTextColor(fg)
            background = drawable
            stateListAnimator = null
            isAllCaps = false
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(padH, padV, padH, padV)
            minHeight = Ui.dp(this@MainActivity, 40)
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            ).apply { rightMargin = Ui.dp(this@MainActivity, 8) }
            setOnClickListener { onClick() }
        }
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    private fun truncate(s: String, max: Int): String =
        if (s.length <= max) s else s.substring(0, max - 1) + "…"

    private companion object {
        const val TAG = "DeviceIntelligence.Sample"
        const val JSON_TAG = "DeviceIntelligence.Json"
    }
}
