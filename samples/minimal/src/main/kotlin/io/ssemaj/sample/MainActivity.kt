package io.ssemaj.sample

import android.animation.LayoutTransition
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
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
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.Button
import android.widget.ImageView
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.time.Duration.Companion.milliseconds

/**
 * Telemetry viewer for the DeviceIntelligence sample.
 *
 * UI is fully programmatic — no XML layouts beyond launcher icons,
 * theme colours, and string resources. Animations all use framework
 * primitives (`ObjectAnimator`, `ValueAnimator`, `LayoutTransition`,
 * `view.animate()`) so the sample stays AndroidX-free in its UI
 * layer.
 */
class MainActivity : Activity() {

    private val mainHandler = Handler(Looper.getMainLooper())

    private val activityScope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private var autoCollectJob: Job? = null

    private lateinit var ui: Ui
    private lateinit var rootLinear: LinearLayout

    private lateinit var heroContainer: LinearLayout
    private lateinit var heroBrandChip: ImageView
    private lateinit var heroBrandLabel: TextView
    private lateinit var heroSubtitle: TextView
    private lateinit var heroMeta: TextView
    private lateinit var heroChips: FlowLayout
    private var heroScanAnim: ObjectAnimator? = null
    private var heroLastFindingCount: Int = -1

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
    private lateinit var jsonChevron: ImageView
    private var jsonExpanded: Boolean = false

    private lateinit var autoBtn: Button
    private lateinit var autoBtnDot: ImageView
    private lateinit var recollectBtn: Button

    @Volatile private var lastReport: TelemetryReport? = null
    @Volatile private var lastJson: String = ""
    @Volatile private var collectInFlight: Boolean = false
    private var autoCollectOn: Boolean = false

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
        animateInitialReveal()
        runCollect(initial = true)
    }

    override fun onDestroy() {
        super.onDestroy()
        mainHandler.removeCallbacksAndMessages(null)
        stopHeroScan()
        autoCollectJob?.cancel()
        activityScope.cancel()
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
            // LayoutTransition makes any add / remove / size change inside
            // the root container animate (cards, finding rows, detector
            // rows, JSON expand). APPEARING + DISAPPEARING + CHANGING are
            // enabled so newly-added rows fade in and the JSON card grows
            // its height smoothly when toggled.
            layoutTransition = LayoutTransition().apply {
                enableTransitionType(LayoutTransition.CHANGING)
                setDuration(180)
            }
        }
        rootLinear = root

        // ---- hero ----
        heroContainer = ui.heroBanner(this).also { root.addView(it) }
        val brandRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        heroBrandChip = ImageView(this).apply {
            setImageResource(R.drawable.ic_chip)
            imageTintList = ColorStateList.valueOf(ui.palette.subtitle)
            scaleType = ImageView.ScaleType.FIT_CENTER
            layoutParams = LinearLayout.LayoutParams(
                Ui.dp(this@MainActivity, 18),
                Ui.dp(this@MainActivity, 18),
            ).apply { rightMargin = Ui.dp(this@MainActivity, 8) }
        }
        heroBrandLabel = TextView(this).apply {
            textSize = 12f
            setTextColor(ui.palette.subtitle)
            text = "DEVICEINTELLIGENCE"
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            letterSpacing = 0.12f
        }
        brandRow.addView(heroBrandChip)
        brandRow.addView(heroBrandLabel)
        heroContainer.addView(brandRow)

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
        heroContainer.addView(heroSubtitle)
        heroContainer.addView(heroMeta)
        heroContainer.addView(heroChips)

        // ---- actions ----
        val actionsCard = ui.card(this).also { root.addView(it) }
        actionsCard.addView(ui.titleRowWithIcon(this, R.drawable.ic_refresh, "Actions"))
        actionsCard.addView(
            ui.subtitle(
                this,
                "Re-collect re-runs every detector. Auto re-collects every " +
                    "${AUTO_COLLECT_INTERVAL_MS / 1000}s — useful for watching " +
                    "integrity.art catch a Frida / LSPosed attach in real " +
                    "time. Copy puts the full telemetry blob on the clipboard.",
            ),
        )
        val actionsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 12) }
        }
        recollectBtn = makeButton(
            label = "Re-collect",
            tone = Ui.Tone.INFO,
            iconRes = R.drawable.ic_refresh,
            onClick = { runCollect(initial = false) },
        )
        actionsRow.addView(recollectBtn)
        actionsRow.addView(buildAutoButton())
        actionsRow.addView(
            makeButton(
                label = "Copy",
                tone = Ui.Tone.NEUTRAL,
                iconRes = R.drawable.ic_copy,
                onClick = { copyJsonToClipboard() },
            ),
        )
        actionsCard.addView(actionsRow)

        // ---- device snapshot ----
        val deviceCard = ui.card(this).also { root.addView(it) }
        deviceCard.addView(ui.titleRowWithIcon(this, R.drawable.ic_device, "Device"))
        deviceCard.addView(
            ui.subtitle(this, "Hardware + OS facts. Used for cohorting and emulator heuristics."),
        )
        deviceCardBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
            layoutTransition = LayoutTransition().apply { setDuration(160) }
        }
        deviceCard.addView(deviceCardBody)

        // ---- app snapshot ----
        val appCard = ui.card(this).also { root.addView(it) }
        appCard.addView(ui.titleRowWithIcon(this, R.drawable.ic_app_box, "App"))
        appCard.addView(ui.subtitle(this, "Identity, install attribution, and signer chain."))
        appCardBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = Ui.dp(this@MainActivity, 8) }
            layoutTransition = LayoutTransition().apply { setDuration(160) }
        }
        appCard.addView(appCardBody)

        // ---- findings ----
        findingsCard = ui.card(this).also { root.addView(it) }
        findingsTitleRow = ui.titleRowWithIcon(
            context = this,
            iconRes = R.drawable.ic_diamond,
            titleText = "Findings",
            accessories = listOf(ui.badge(this, "0", Ui.Tone.NEUTRAL)),
        )
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
            layoutTransition = LayoutTransition().apply { setDuration(180) }
        }
        findingsCard.addView(findingsBody)

        // ---- detectors ----
        val detectorsCard = ui.card(this).also { root.addView(it) }
        detectorsTitleRow = ui.titleRowWithIcon(
            context = this,
            iconRes = R.drawable.ic_radar,
            titleText = "Detectors",
            accessories = listOf(ui.badge(this, "0", Ui.Tone.NEUTRAL)),
        )
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
            layoutTransition = LayoutTransition().apply { setDuration(180) }
        }
        detectorsCard.addView(detectorsBody)

        // ---- json (collapsible) ----
        val jsonCard = ui.card(this).also { root.addView(it) }
        jsonChevron = ImageView(this).apply {
            setImageResource(R.drawable.ic_chevron_down)
            imageTintList = ColorStateList.valueOf(ui.palette.subtitle)
            scaleType = ImageView.ScaleType.FIT_CENTER
            layoutParams = LinearLayout.LayoutParams(
                Ui.dp(this@MainActivity, 18),
                Ui.dp(this@MainActivity, 18),
            )
        }
        jsonToggleBtn = makeButton(
            label = "Show",
            tone = Ui.Tone.NEUTRAL,
            iconRes = null,
            onClick = { toggleJson() },
        ).apply {
            // Override makeButton's weighted layout — JSON toggle sits in
            // a titleRow accessory slot, so it should hug its content.
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        jsonCard.addView(
            ui.titleRowWithIcon(
                context = this,
                iconRes = R.drawable.ic_braces,
                titleText = "Telemetry JSON",
                accessories = listOf(jsonChevron, jsonToggleBtn),
            ),
        )
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

    /**
     * Build the Auto button: same look as [makeButton] but with a
     * [Ui.pulsingDot] glued onto the leading edge that we can
     * start / stop in [toggleAutoCollect].
     */
    private fun buildAutoButton(): View {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            val (_, bg) = ui.palette.toneNeutral
            background = GradientDrawable().apply {
                setColor(bg)
                cornerRadius = Ui.dp(this@MainActivity, 12).toFloat()
            }
            val padH = Ui.dp(this@MainActivity, 14)
            val padV = Ui.dp(this@MainActivity, 8)
            setPadding(padH, padV, padH, padV)
            minimumHeight = Ui.dp(this@MainActivity, 40)
            isClickable = true
            isFocusable = true
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            ).apply { rightMargin = Ui.dp(this@MainActivity, 8) }
            setOnClickListener {
                pressPulse(this)
                toggleAutoCollect()
            }
        }
        autoBtnDot = ui.pulsingDot(this, tone = Ui.Tone.OK).apply {
            alpha = 0f
            layoutParams = LinearLayout.LayoutParams(
                Ui.dp(this@MainActivity, 10),
                Ui.dp(this@MainActivity, 10),
            ).apply { rightMargin = Ui.dp(this@MainActivity, 8) }
        }
        autoBtn = Button(this).apply {
            text = autoButtonLabel()
            textSize = 12f
            setTextColor(ui.palette.toneNeutral.first)
            background = null
            stateListAnimator = null
            isAllCaps = false
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 0)
            isClickable = false
            isFocusable = false
        }
        container.addView(autoBtnDot)
        container.addView(autoBtn)
        return container
    }

    // ---- collect & render --------------------------------------------------

    private fun runCollect(initial: Boolean) {
        if (collectInFlight) return
        collectInFlight = true
        startHeroScan()
        activityScope.launch {
            val report = runCatching { DeviceIntelligence.collect(this@MainActivity) }
                .onFailure { Log.e(TAG, "DeviceIntelligence.collect threw", it) }
                .getOrNull()
            try {
                applyReport(report, initial = initial)
            } finally {
                collectInFlight = false
                stopHeroScan()
            }
        }
    }

    private fun applyReport(report: TelemetryReport?, initial: Boolean) {
        if (report == null) {
            jsonView.text = "(collect failed — see logcat)"
            Log.w(TAG, "collect failed")
            return
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

    private fun startAutoCollect() {
        autoCollectJob?.cancel()
        autoCollectJob = DeviceIntelligence
            .observe(
                context = this,
                interval = AUTO_COLLECT_INTERVAL_MS.milliseconds,
            )
            .onEach { applyReport(it, initial = false) }
            .launchIn(activityScope)
    }

    private fun stopAutoCollect() {
        autoCollectJob?.cancel()
        autoCollectJob = null
    }

    private fun toggleAutoCollect() {
        autoCollectOn = !autoCollectOn
        autoBtn.text = autoButtonLabel()
        if (autoCollectOn) {
            startAutoCollect()
            autoBtnDot.animate().alpha(1f).setDuration(180).start()
            ui.startPulsingDot(autoBtnDot)
            toast("Auto-collect on (${AUTO_COLLECT_INTERVAL_MS / 1000}s)")
        } else {
            stopAutoCollect()
            ui.stopPulsingDot(autoBtnDot)
            autoBtnDot.animate().alpha(0f).setDuration(140).start()
            toast("Auto-collect off")
        }
    }

    private fun autoButtonLabel(): String =
        if (autoCollectOn) "Auto · on" else "Auto · off"

    override fun onPause() {
        super.onPause()
        if (autoCollectOn) stopAutoCollect()
        if (::autoBtnDot.isInitialized) ui.stopPulsingDot(autoBtnDot)
    }

    override fun onResume() {
        super.onResume()
        if (autoCollectOn) {
            startAutoCollect()
            ui.startPulsingDot(autoBtnDot)
        }
    }

    // ---- rendering helpers -------------------------------------------------

    private fun renderHero(report: TelemetryReport) {
        val total = report.summary.totalFindings
        val critical = report.summary.findingsBySeverity[Severity.CRITICAL] ?: 0
        val high = report.summary.findingsBySeverity[Severity.HIGH] ?: 0

        val tone = when {
            critical > 0 -> Ui.Tone.BAD
            high > 0 -> Ui.Tone.WARN
            total > 0 -> Ui.Tone.INFO
            else -> Ui.Tone.OK
        }
        ui.tintHero(heroContainer, tone)
        heroBrandChip.imageTintList = ColorStateList.valueOf(ui.toneFg(tone))
        heroBrandLabel.setTextColor(ui.toneFg(tone))

        animateHeroSubtitle(total)

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
            addHeroChip("inconclusive", report.summary.detectorsInconclusive.size, Ui.Tone.NEUTRAL)
        }
        if (report.summary.detectorsErrored.isNotEmpty()) {
            addHeroChip("errors", report.summary.detectorsErrored.size, Ui.Tone.BAD)
        }
    }

    private fun animateHeroSubtitle(total: Int) {
        val from = heroLastFindingCount.coerceAtLeast(0)
        if (heroLastFindingCount < 0 || from == total) {
            heroSubtitle.text = subtitleForCount(total)
            heroLastFindingCount = total
            return
        }
        ValueAnimator.ofInt(from, total).apply {
            duration = 380
            interpolator = DecelerateInterpolator()
            addUpdateListener { va ->
                val n = va.animatedValue as Int
                heroSubtitle.text = subtitleForCount(n)
            }
            start()
        }
        heroLastFindingCount = total
    }

    private fun subtitleForCount(n: Int): String = when {
        n == 0 -> "All clear"
        n == 1 -> "1 finding"
        else -> "$n findings"
    }

    private fun addHeroChip(label: String, count: Int, tone: Ui.Tone) {
        ui.addToBadgeRow(heroChips, ui.badge(this, "$label · $count", tone))
    }

    private fun startHeroScan() {
        if (!::heroBrandChip.isInitialized) return
        if (heroScanAnim?.isStarted == true) return
        heroScanAnim = ObjectAnimator.ofFloat(heroBrandChip, "rotation", 0f, 360f).apply {
            duration = 1100
            repeatCount = ObjectAnimator.INFINITE
            interpolator = LinearInterpolator()
            start()
        }
    }

    private fun stopHeroScan() {
        heroScanAnim?.cancel()
        heroScanAnim = null
        if (::heroBrandChip.isInitialized) {
            heroBrandChip.animate().rotation(0f).setDuration(160).start()
        }
    }

    private fun renderDevice(device: DeviceContext) {
        deviceCardBody.removeAllViews()
        deviceCardBody.addView(ui.kv(this, "manufacturer", device.manufacturer))
        deviceCardBody.addView(ui.kv(this, "model", device.model))
        device.device?.let { deviceCardBody.addView(ui.kv(this, "codename", it)) }
        deviceCardBody.addView(ui.kv(this, "android", "API ${device.sdkInt}"))
        deviceCardBody.addView(ui.kv(this, "abi", device.abi))
        if (device.socManufacturer != null || device.socModel != null) {
            val soc = listOfNotNull(device.socManufacturer, device.socModel).joinToString(" ")
            deviceCardBody.addView(ui.kv(this, "soc", soc))
        }
        device.eglImplementation?.let {
            deviceCardBody.addView(ui.kv(this, "gpu", "$it / GLES ${device.glEsVersion ?: "?"}"))
        }
        device.totalRamMb?.let { deviceCardBody.addView(ui.kv(this, "ram", "${it} MiB")) }
        device.cpuCores?.let { deviceCardBody.addView(ui.kv(this, "cpu cores", it.toString())) }
        if (device.screenResolution != null || device.screenDensityDpi != null) {
            val text = buildString {
                device.screenResolution?.let { append(it) }
                if (device.screenDensityDpi != null) {
                    if (isNotEmpty()) append("  ")
                    append("${device.screenDensityDpi}dpi")
                }
                device.displayRefreshRateHz?.let {
                    if (isNotEmpty()) append("  ")
                    append("%.0fHz".format(it))
                }
            }
            deviceCardBody.addView(ui.kv(this, "screen", text))
        }
        device.defaultLocale?.let { deviceCardBody.addView(ui.kv(this, "locale", it)) }
        device.timezoneId?.let {
            val offset = device.timezoneOffsetMinutes
            val offsetStr = if (offset != null)
                " (UTC%+d:%02d)".format(offset / 60, kotlin.math.abs(offset % 60))
            else ""
            deviceCardBody.addView(ui.kv(this, "timezone", "$it$offsetStr"))
        }
        device.batteryTechnology?.let {
            val plug = device.batteryPlugType?.let { p -> if (p == "none") "" else " · $p" } ?: ""
            deviceCardBody.addView(ui.kv(this, "battery", "$it$plug"))
        }
        device.sensorCount?.let { deviceCardBody.addView(ui.kv(this, "sensors", it.toString())) }
        device.bootCount?.let { deviceCardBody.addView(ui.kv(this, "boot count", it.toString())) }
        device.playServicesVersionCode?.let {
            deviceCardBody.addView(ui.kv(this, "play services", it.toString()))
        }
        deviceCardBody.addView(ui.kv(this, "fingerprint", truncate(device.fingerprint, 56)))

        val badges = ui.badgeRow(this, topMargin = 12)
        device.hasFingerprintHw?.let {
            ui.addToBadgeRow(badges, ui.badge(this, if (it) "fingerprint hw" else "no fingerprint hw",
                if (it) Ui.Tone.OK else Ui.Tone.NEUTRAL))
        }
        device.hasTelephonyHw?.let {
            ui.addToBadgeRow(badges, ui.badge(this, if (it) "telephony" else "no telephony",
                if (it) Ui.Tone.OK else Ui.Tone.NEUTRAL))
        }
        device.vpnActive?.let {
            ui.addToBadgeRow(badges, ui.badge(this, if (it) "vpn active" else "no vpn",
                if (it) Ui.Tone.WARN else Ui.Tone.NEUTRAL))
        }
        device.strongboxAvailable?.let {
            ui.addToBadgeRow(badges, ui.badge(this, if (it) "strongbox hw" else "no strongbox",
                if (it) Ui.Tone.OK else Ui.Tone.NEUTRAL))
        }
        device.deviceSecure?.let {
            ui.addToBadgeRow(badges, ui.badge(this, if (it) "lockscreen set" else "no lockscreen",
                if (it) Ui.Tone.OK else Ui.Tone.WARN))
        }
        device.biometricsEnrolled?.let {
            if (it) ui.addToBadgeRow(badges, ui.badge(this, "biometrics", Ui.Tone.OK))
        }
        device.adbEnabled?.let {
            if (it) ui.addToBadgeRow(badges, ui.badge(this, "adb on", Ui.Tone.WARN))
        }
        device.developerOptionsEnabled?.let {
            if (it) ui.addToBadgeRow(badges, ui.badge(this, "dev options", Ui.Tone.WARN))
        }
        device.autoTimeEnabled?.let {
            if (!it) ui.addToBadgeRow(badges, ui.badge(this, "manual clock", Ui.Tone.WARN))
        }
        device.thermalStatus?.let {
            if (it != "none") ui.addToBadgeRow(badges, ui.badge(this, "thermal: $it",
                if (it == "light" || it == "moderate") Ui.Tone.WARN else Ui.Tone.BAD))
        }
        device.playServicesAvailability?.let {
            if (it != "success") ui.addToBadgeRow(badges, ui.badge(this, "gms: $it", Ui.Tone.WARN))
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
                appCardBody.addView(ui.kv(this, "signer count", app.signerCertSha256.size.toString()))
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
                    ui.addToBadgeRow(badges, ui.badge(this, "software-backed keymint", Ui.Tone.WARN))
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
                ui.addToBadgeRow(badges, ui.badge(this,
                    if (it) "bootloader locked" else "bootloader unlocked",
                    if (it) Ui.Tone.OK else Ui.Tone.BAD))
            }
            att.verdictDeviceRecognition?.let { verdict ->
                verdict.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach { token ->
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
            ui.badge(this, findings.size.toString(),
                if (findings.isEmpty()) Ui.Tone.OK else Ui.Tone.WARN),
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
            severityIcon = severityIcon(finding.severity),
        )
    }

    private fun severityShort(s: Severity): String = when (s) {
        Severity.CRITICAL -> "CRIT"
        Severity.HIGH -> "HIGH"
        Severity.MEDIUM -> "MED"
        Severity.LOW -> "LOW"
    }

    private fun severityIcon(s: Severity): Int = when (s) {
        Severity.CRITICAL -> R.drawable.ic_alert
        Severity.HIGH -> R.drawable.ic_warning
        Severity.MEDIUM -> R.drawable.ic_info
        Severity.LOW -> R.drawable.ic_info
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
                    statusIcon = detectorStatusIcon(det),
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

    private fun detectorStatusIcon(det: DetectorReport): Int = when (det.status) {
        DetectorStatus.OK -> when {
            det.findings.isEmpty() -> R.drawable.ic_check
            det.findings.any { it.severity == Severity.CRITICAL } -> R.drawable.ic_alert
            det.findings.any { it.severity == Severity.HIGH } -> R.drawable.ic_warning
            else -> R.drawable.ic_info
        }
        DetectorStatus.INCONCLUSIVE -> R.drawable.ic_inconclusive
        DetectorStatus.ERROR -> R.drawable.ic_alert
    }

    private fun severityTone(s: Severity): Ui.Tone = when (s) {
        Severity.CRITICAL -> Ui.Tone.BAD
        Severity.HIGH -> Ui.Tone.WARN
        Severity.MEDIUM -> Ui.Tone.INFO
        Severity.LOW -> Ui.Tone.NEUTRAL
    }

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

    /**
     * Stagger every direct child of [rootLinear] into view: each card
     * starts at alpha 0 / translationY +24dp and animates to the rest
     * state with a slight per-card delay so the eye reads top-to-bottom.
     */
    private fun animateInitialReveal() {
        val baseDelay = 60L
        val perCard = 40L
        val translate = Ui.dp(this, 24).toFloat()
        for (i in 0 until rootLinear.childCount) {
            val card = rootLinear.getChildAt(i)
            card.alpha = 0f
            card.translationY = translate
            card.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(280)
                .setStartDelay(baseDelay + i * perCard)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    /**
     * Brief scale-down + bounce-back press feedback. Driven manually
     * (instead of via stateListAnimator) because makeButton zeroes the
     * default state animator to keep the flat look.
     */
    private fun pressPulse(view: View) {
        view.animate()
            .scaleX(0.96f).scaleY(0.96f)
            .setDuration(80)
            .withEndAction {
                view.animate()
                    .scaleX(1f).scaleY(1f)
                    .setInterpolator(OvershootInterpolator(2.4f))
                    .setDuration(180)
                    .start()
            }
            .start()
    }

    // ---- actions -----------------------------------------------------------

    private fun toggleJson() {
        jsonExpanded = !jsonExpanded
        jsonCardBody.visibility = if (jsonExpanded) View.VISIBLE else View.GONE
        jsonToggleBtn.text = if (jsonExpanded) "Hide" else "Show"
        jsonChevron.animate()
            .rotation(if (jsonExpanded) 180f else 0f)
            .setDuration(200)
            .setInterpolator(AccelerateDecelerateInterpolator())
            .start()
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

    /**
     * Tone-tinted pill button. If [iconRes] is non-null a 14dp tinted
     * icon is drawn on the leading edge with 6dp gap to the label.
     */
    private fun makeButton(
        label: String,
        tone: Ui.Tone,
        iconRes: Int?,
        onClick: () -> Unit,
    ): Button {
        val (fg, bg) = when (tone) {
            Ui.Tone.OK -> ui.palette.toneOk
            Ui.Tone.BAD -> ui.palette.toneBad
            Ui.Tone.WARN -> ui.palette.toneWarn
            Ui.Tone.INFO -> ui.palette.toneInfo
            Ui.Tone.NEUTRAL -> ui.palette.toneNeutral
            Ui.Tone.ACCENT -> ui.palette.toneAccent
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
            if (iconRes != null) {
                val drawableLeft = resources.getDrawable(iconRes, theme).apply {
                    val sizePx = Ui.dp(this@MainActivity, 14)
                    setBounds(0, 0, sizePx, sizePx)
                    setTint(fg)
                }
                setCompoundDrawables(drawableLeft, null, null, null)
                compoundDrawablePadding = Ui.dp(this@MainActivity, 6)
            }
            setOnClickListener {
                pressPulse(this)
                onClick()
            }
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

        /** Auto-collect period. 2 s strikes a usable balance between
         *  "live enough to see Frida attach" and "doesn't drown
         *  logcat or burn battery". */
        const val AUTO_COLLECT_INTERVAL_MS = 2_000L
    }
}
