package io.ssemaj.sample

import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.animation.ArgbEvaluator
import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.view.animation.OvershootInterpolator
import android.widget.Button
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.max
import kotlin.math.min

/**
 * Tiny programmatic-UI toolkit for the sample app. Kept self-contained
 * (no AndroidX in the UI layer, no XML layouts) so the sample stays a
 * one-file smoke-test artifact rather than a full app project.
 *
 * Instantiated once per [android.app.Activity] via [forContext], which
 * picks a light or dark [Palette] based on the current
 * `uiMode` configuration. All colors flow through the palette so the
 * app respects the system theme.
 */
internal class Ui(val palette: Palette) {

    enum class Tone { OK, BAD, WARN, INFO, NEUTRAL, ACCENT }

    private fun tonePair(t: Tone): Pair<Int, Int> = when (t) {
        Tone.OK -> palette.toneOk
        Tone.BAD -> palette.toneBad
        Tone.WARN -> palette.toneWarn
        Tone.INFO -> palette.toneInfo
        Tone.NEUTRAL -> palette.toneNeutral
        Tone.ACCENT -> palette.toneAccent
    }

    /** Foreground colour for a tone, used to tint icons drawn next to a label. */
    fun toneFg(t: Tone): Int = tonePair(t).first

    /**
     * Vertical card container with a rounded background and a 1dp
     * border. Adds a small bottom margin so cards stack with breathing
     * room.
     */
    fun card(context: Context): LinearLayout {
        val pad = dp(context, 16)
        val radius = dp(context, 16).toFloat()
        val border = dp(context, 1)

        val bg = GradientDrawable().apply {
            setColor(palette.cardBg)
            cornerRadius = radius
            setStroke(border, palette.cardBorder)
        }
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            background = bg
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(context, 12) }
        }
    }

    /**
     * Hero banner: a tall, color-toned rounded panel intended for the
     * top-of-screen verdict summary. Returns the container so callers
     * can populate it with title/subtitle text and re-tint by calling
     * [tintHero].
     */
    fun heroBanner(context: Context): LinearLayout {
        val radius = dp(context, 20).toFloat()
        val pad = dp(context, 20)
        val drawable = GradientDrawable().apply {
            setColor(palette.toneNeutral.second)
            cornerRadius = radius
        }
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            background = drawable
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { bottomMargin = dp(context, 14) }
        }
    }

    /**
     * Re-color a hero produced by [heroBanner] to the given tone.
     * Crossfades the background color over [animDurationMs] using
     * [ValueAnimator] + [android.animation.ArgbEvaluator] so a tone
     * change feels like a tint, not a flash.
     */
    fun tintHero(hero: LinearLayout, tone: Tone, animDurationMs: Long = 240) {
        val drawable = hero.background as GradientDrawable
        val target = tonePair(tone).second
        // Best-effort read of the current colour. GradientDrawable doesn't
        // expose its current solid color via a public API across all
        // platform levels, so we tag it ourselves on every transition.
        val current = (hero.getTag(R_ID_HERO_COLOR) as? Int) ?: target
        if (current == target) return
        ValueAnimator.ofArgb(current, target).apply {
            duration = animDurationMs
            addUpdateListener { drawable.setColor(it.animatedValue as Int) }
            start()
        }
        hero.setTag(R_ID_HERO_COLOR, target)
    }

    fun title(context: Context, text: String): TextView = TextView(context).apply {
        this.text = text
        textSize = 17f
        setTextColor(palette.title)
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }

    fun subtitle(context: Context, text: String, topMargin: Int = 4): TextView =
        TextView(context).apply {
            this.text = text
            textSize = 13f
            setTextColor(palette.subtitle)
            setLineSpacing(0f, 1.15f)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { this.topMargin = dp(context, topMargin) }
        }

    /** Mono-spaced paragraph. Used for hashes, addresses, and JSON. */
    fun mono(context: Context, text: CharSequence, sizeSp: Float = 11f): TextView =
        TextView(context).apply {
            this.text = text
            textSize = sizeSp
            setTextColor(palette.mono)
            typeface = Typeface.MONOSPACE
            setLineSpacing(0f, 1.2f)
            setTextIsSelectable(true)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 6) }
        }

    /**
     * Small inline pill (badge) to color-code state. Always renders
     * on a single line; if the text is longer than the parent can
     * accommodate the badge ellipsizes at the end so it never wraps
     * mid-word inside its rounded background.
     */
    fun badge(context: Context, text: String, tone: Tone): TextView {
        val (fg, bg) = tonePair(tone)
        val pad = dp(context, 8)
        val padV = dp(context, 3)
        val radius = dp(context, 999).toFloat()
        val drawable = GradientDrawable().apply {
            setColor(bg)
            cornerRadius = radius
        }
        return TextView(context).apply {
            this.text = text
            textSize = 11f
            setTextColor(fg)
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            setPadding(pad, padV, pad, padV)
            background = drawable
            includeFontPadding = false
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
        }
    }

    /**
     * Square [ImageView] holding a vector drawable, sized in dp and
     * tinted with [tint]. The default tint pulls from the palette's
     * subtitle colour so the icon reads as secondary unless callers
     * explicitly upgrade it (via [Tone] -> [toneFg]).
     */
    fun iconView(
        context: Context,
        drawableRes: Int,
        sizeDp: Int = 18,
        tint: Int = palette.subtitle,
    ): ImageView = ImageView(context).apply {
        setImageResource(drawableRes)
        imageTintList = ColorStateList.valueOf(tint)
        scaleType = ImageView.ScaleType.FIT_CENTER
        layoutParams = LinearLayout.LayoutParams(dp(context, sizeDp), dp(context, sizeDp))
    }

    /**
     * Horizontal row that places the [titleText] flush-left and an
     * optional list of [accessories] (typically badges) flush-right.
     * Used for card title bars.
     */
    fun titleRow(
        context: Context,
        titleText: String,
        accessories: List<View> = emptyList(),
    ): LinearLayout = titleRowWithIcon(context, iconRes = null, titleText = titleText, accessories = accessories)

    /**
     * Like [titleRow] but with an optional leading icon glyph that
     * tints to match [palette.title]. Used to give every card a
     * recognisable mark next to its title.
     */
    fun titleRowWithIcon(
        context: Context,
        iconRes: Int?,
        titleText: String,
        accessories: List<View> = emptyList(),
    ): LinearLayout {
        val leading = iconRes?.let { res ->
            iconView(context, res, sizeDp = 18, tint = palette.title)
        }
        return titleRowWithLeading(context, leading, titleText, accessories)
    }

    /**
     * Title row variant that accepts an arbitrary [leading] view (e.g.
     * a [FrameLayout] stacking two icons, or an animated container).
     * Used by the Detectors card so the radar can have a stationary
     * dish and a separately-rotating sweep arm.
     */
    fun titleRowWithLeading(
        context: Context,
        leading: View?,
        titleText: String,
        accessories: List<View> = emptyList(),
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        if (leading != null) {
            val sizePx = dp(context, 18)
            val lp = (leading.layoutParams as? LinearLayout.LayoutParams)
                ?: LinearLayout.LayoutParams(sizePx, sizePx)
            lp.width = sizePx
            lp.height = sizePx
            lp.rightMargin = dp(context, 8)
            leading.layoutParams = lp
            row.addView(leading)
        }
        row.addView(
            title(context, titleText).apply {
                layoutParams = LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f,
                )
            },
        )
        for ((i, acc) in accessories.withIndex()) {
            val lp = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            if (i > 0) lp.leftMargin = dp(context, 6)
            acc.layoutParams = lp
            row.addView(acc)
        }
        return row
    }

    /**
     * Compact `key  value` row used in Device / App snapshot cards.
     * Key is muted, value is mono dark.
     */
    fun kv(context: Context, key: String, value: String?): LinearLayout =
        kvWithIcon(context, iconRes = null, key = key, value = value)

    /**
     * Like [kv] but with an optional 14dp leading icon column. The icon
     * tints to [palette.subtitle] (or [iconTint] if provided) so it reads
     * as decorative metadata next to the key. When [iconRes] is null the
     * icon column is still allocated so all rows in a card line up
     * vertically — important for the Device / App snapshots where some
     * rows have icons and some don't.
     */
    fun kvWithIcon(
        context: Context,
        iconRes: Int?,
        key: String,
        value: String?,
        iconTint: Int = palette.subtitle,
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 5) }
        }
        // Reserve a 14+8 = 22dp slot whether or not we draw an icon, so
        // every kv row in the same card aligns its key column.
        val iconSlotPx = dp(context, 22)
        if (iconRes != null) {
            val iv = iconView(context, iconRes, sizeDp = 14, tint = iconTint)
            iv.layoutParams = LinearLayout.LayoutParams(
                dp(context, 14),
                dp(context, 14),
            ).apply { rightMargin = dp(context, 8) }
            row.addView(iv)
        } else {
            row.addView(
                View(context).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        iconSlotPx,
                        dp(context, 14),
                    )
                },
            )
        }
        row.addView(
            TextView(context).apply {
                text = key
                textSize = 11.5f
                setTextColor(palette.muted)
                layoutParams = LinearLayout.LayoutParams(
                    dp(context, 110),
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                )
            },
        )
        row.addView(
            TextView(context).apply {
                text = value ?: "—"
                textSize = 11.5f
                setTextColor(if (value == null) palette.muted else palette.mono)
                typeface = Typeface.MONOSPACE
                setTextIsSelectable(value != null)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                )
            },
        )
        return row
    }

    /**
     * Wrapping row of badges. Children are laid out left-to-right and
     * spill onto new lines when they don't fit, so a long verdict
     * chip never gets clipped or makes the screen scroll horizontally.
     */
    fun badgeRow(context: Context, topMargin: Int = 8): FlowLayout = FlowLayout(context).apply {
        horizontalSpacing = dp(context, 6)
        verticalSpacing = dp(context, 6)
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        ).apply { this.topMargin = dp(context, topMargin) }
    }

    fun addToBadgeRow(parent: FlowLayout, badge: View) {
        val lp = ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT,
        )
        parent.addView(badge, lp)
    }

    /**
     * One row in the Findings list: severity icon + pill on the left,
     * then a vertical block of `kind` (mono bold), `subject` (muted),
     * and `message` (subtitle color).
     */
    fun findingRow(
        context: Context,
        severityLabel: String,
        tone: Tone,
        kind: String,
        subject: String?,
        message: String,
        severityIcon: Int? = null,
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 10) }
        }
        // Icon column (16dp wide, tone-tinted). Sits flush with the
        // first line of the kind text so readers' eyes go icon -> kind.
        if (severityIcon != null) {
            val ic = iconView(context, severityIcon, sizeDp = 16, tint = toneFg(tone))
            ic.layoutParams = LinearLayout.LayoutParams(
                dp(context, 16), dp(context, 16),
            ).apply {
                rightMargin = dp(context, 8)
                topMargin = dp(context, 2)
            }
            row.addView(ic)
        }
        row.addView(
            badge(context, severityLabel, tone).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply {
                    rightMargin = dp(context, 10)
                    topMargin = dp(context, 2)
                }
            },
        )
        val col = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f,
            )
        }
        col.addView(
            TextView(context).apply {
                text = kind
                textSize = 12.5f
                setTextColor(palette.title)
                typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            },
        )
        if (!subject.isNullOrBlank()) {
            col.addView(
                TextView(context).apply {
                    text = subject
                    textSize = 11.5f
                    setTextColor(palette.muted)
                    typeface = Typeface.MONOSPACE
                    layoutParams = LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                    ).apply { topMargin = dp(context, 1) }
                },
            )
        }
        col.addView(
            TextView(context).apply {
                text = message
                textSize = 12.5f
                setTextColor(palette.subtitle)
                setLineSpacing(0f, 1.15f)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { topMargin = dp(context, 2) }
            },
        )
        row.addView(col)
        return row
    }

    /**
     * One row in the Detectors list: status icon + id (mono), status
     * pill, then `Nms · K finding(s)` on the right.
     */
    fun detectorRow(
        context: Context,
        id: String,
        statusLabel: String,
        statusTone: Tone,
        rightLabel: String,
        statusIcon: Int? = null,
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 8) }
        }
        if (statusIcon != null) {
            val ic = iconView(context, statusIcon, sizeDp = 14, tint = toneFg(statusTone))
            ic.layoutParams = LinearLayout.LayoutParams(
                dp(context, 14), dp(context, 14),
            ).apply { rightMargin = dp(context, 8) }
            row.addView(ic)
        }
        row.addView(
            TextView(context).apply {
                text = id
                textSize = 11.5f
                setTextColor(palette.title)
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(
                    0,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    1f,
                )
            },
        )
        row.addView(
            badge(context, statusLabel, statusTone).apply {
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ).apply { rightMargin = dp(context, 8) }
            },
        )
        row.addView(
            TextView(context).apply {
                text = rightLabel
                textSize = 11f
                setTextColor(palette.muted)
                typeface = Typeface.MONOSPACE
            },
        )
        return row
    }

    /**
     * "Live" indicator: a small filled circle whose alpha pulses
     * 0.35 -> 1.0 forever on a 900ms cycle. Used next to the
     * Auto button label so the user can see at a glance that the
     * observe() Flow is emitting.
     */
    fun pulsingDot(context: Context, tone: Tone = Tone.OK): ImageView {
        val view = iconView(context, R.drawable.ic_pulse_dot, sizeDp = 10, tint = toneFg(tone))
        val anim = ObjectAnimator.ofFloat(view, "alpha", 1f, 0.35f, 1f).apply {
            duration = 900
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
        }
        view.setTag(R_ID_PULSE_ANIM, anim)
        return view
    }

    fun startPulsingDot(view: View) {
        (view.getTag(R_ID_PULSE_ANIM) as? ObjectAnimator)?.let {
            if (!it.isStarted) it.start()
        }
    }

    fun stopPulsingDot(view: View) {
        (view.getTag(R_ID_PULSE_ANIM) as? ObjectAnimator)?.let {
            if (it.isStarted) it.cancel()
            view.alpha = 1f
        }
    }

    /**
     * Brief background-color flash on [view], starting from the
     * tone's background color and animating alpha → transparent.
     * Used to spotlight a row that just changed (e.g. a finding that
     * appeared on the most recent collect). Self-cleans the
     * background drawable when the animation ends so the row's
     * baseline appearance is restored.
     */
    fun flashRipple(view: View, tone: Tone, durationMs: Long = 720) {
        val (_, bg) = tonePair(tone)
        // Fully transparent end colour with the same RGB so the ARGB
        // evaluator gives a clean alpha-fade with no hue shift.
        val end = bg and 0x00FFFFFF
        ValueAnimator.ofObject(ArgbEvaluator(), bg, end).apply {
            duration = durationMs
            interpolator = DecelerateInterpolator()
            addUpdateListener { va -> view.setBackgroundColor(va.animatedValue as Int) }
            addListener(object : AnimatorListenerAdapter() {
                override fun onAnimationEnd(animation: Animator) {
                    view.background = null
                }
            })
            start()
        }
    }

    /**
     * Quick scale pulse 1 → 1.18 → 1 on [view]. Used on the
     * Findings / Detectors title-row badges when the count changes,
     * so the eye is drawn to the new number without a flash.
     */
    fun pulseBadge(view: View) {
        view.scaleX = 1f
        view.scaleY = 1f
        view.animate()
            .scaleX(1.18f).scaleY(1.18f)
            .setDuration(120)
            .withEndAction {
                view.animate()
                    .scaleX(1f).scaleY(1f)
                    .setInterpolator(OvershootInterpolator(2f))
                    .setDuration(220)
                    .start()
            }
            .start()
    }

    /**
     * Stagger-reveal every direct child of [parent]: each child starts
     * at alpha 0 and translationY [distanceDp], and animates to its
     * rest state with a [perChildMs] offset between siblings. Used by
     * card bodies (Device / App / Findings / Detectors) when their
     * content is rebuilt, so the eye reads top-to-bottom rather than
     * being slammed with everything at once.
     */
    fun staggerReveal(
        parent: ViewGroup,
        baseDelayMs: Long = 0L,
        perChildMs: Long = 18L,
        distanceDp: Int = 8,
        durationMs: Long = 220,
    ) {
        val translate = dp(parent.context, distanceDp).toFloat()
        for (i in 0 until parent.childCount) {
            val child = parent.getChildAt(i)
            child.alpha = 0f
            child.translationY = translate
            child.animate()
                .alpha(1f)
                .translationY(0f)
                .setStartDelay(baseDelayMs + i * perChildMs)
                .setDuration(durationMs)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    /**
     * Stack [overlayRes] on top of [baseRes] inside a square
     * [FrameLayout]. The returned `Pair` exposes the container
     * (for placement in a parent) and the overlay [ImageView] (for
     * rotation). Used by the Detectors title row so the radar's
     * sweep arm can spin while the dishes stay still.
     */
    fun layeredIcon(
        context: Context,
        baseRes: Int,
        overlayRes: Int,
        sizeDp: Int = 18,
        baseTint: Int = palette.title,
        overlayTint: Int = palette.title,
    ): Pair<FrameLayout, ImageView> {
        val sizePx = dp(context, sizeDp)
        val container = FrameLayout(context).apply {
            layoutParams = LinearLayout.LayoutParams(sizePx, sizePx)
        }
        val base = ImageView(context).apply {
            setImageResource(baseRes)
            imageTintList = ColorStateList.valueOf(baseTint)
            scaleType = ImageView.ScaleType.FIT_CENTER
            layoutParams = FrameLayout.LayoutParams(sizePx, sizePx)
        }
        val overlay = ImageView(context).apply {
            setImageResource(overlayRes)
            imageTintList = ColorStateList.valueOf(overlayTint)
            scaleType = ImageView.ScaleType.FIT_CENTER
            alpha = 0f // hidden until startSweep()
            layoutParams = FrameLayout.LayoutParams(sizePx, sizePx)
        }
        container.addView(base)
        container.addView(overlay)
        return container to overlay
    }

    companion object {
        fun forContext(context: Context): Ui {
            val night = (context.resources.configuration.uiMode and
                Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
            return Ui(if (night) Palette.DARK else Palette.LIGHT)
        }

        fun dp(context: Context, value: Int): Int =
            TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP,
                value.toFloat(),
                context.resources.displayMetrics,
            ).toInt()

        // View tag keys. Picked from the framework-reserved range
        // (0x7F... is the AAPT app range) but high enough that the
        // generated R class won't collide. Kept private to Ui so
        // nobody else accidentally reads them.
        private const val R_ID_HERO_COLOR = 0x7F4D0001
        private const val R_ID_PULSE_ANIM = 0x7F4D0002
    }
}

/**
 * All colors used by [Ui]. Two static instances are provided —
 * [LIGHT] and [DARK] — picked at scaffold-build time based on the
 * current `Configuration.uiMode`.
 */
internal data class Palette(
    val pageBg: Int,
    val cardBg: Int,
    val cardBorder: Int,
    val title: Int,
    val subtitle: Int,
    val mono: Int,
    val muted: Int,
    val toneOk: Pair<Int, Int>,
    val toneBad: Pair<Int, Int>,
    val toneWarn: Pair<Int, Int>,
    val toneInfo: Pair<Int, Int>,
    val toneNeutral: Pair<Int, Int>,
    val toneAccent: Pair<Int, Int>,
) {
    companion object {
        val LIGHT = Palette(
            pageBg = 0xFFF6F7F9.toInt(),
            cardBg = 0xFFFFFFFF.toInt(),
            cardBorder = 0xFFE3E5EA.toInt(),
            title = 0xFF111418.toInt(),
            subtitle = 0xFF53575E.toInt(),
            mono = 0xFF1F2328.toInt(),
            muted = 0xFF7A7E86.toInt(),
            toneOk = 0xFF1F7A3A.toInt() to 0xFFE5F4EA.toInt(),
            toneBad = 0xFFB3261E.toInt() to 0xFFFCE7E5.toInt(),
            toneWarn = 0xFFA5560A.toInt() to 0xFFFFF1DD.toInt(),
            toneInfo = 0xFF1A56A8.toInt() to 0xFFE3EEFB.toInt(),
            toneNeutral = 0xFF53575E.toInt() to 0xFFEDEEF0.toInt(),
            // Accent matches the launcher icon (cyan glow over violet
            // chip body). Used by the brand chip in the hero and the
            // "live" pulsing dot when auto-collect is on.
            toneAccent = 0xFF0E5C8C.toInt() to 0xFFD8F1FA.toInt(),
        )

        val DARK = Palette(
            pageBg = 0xFF0F1115.toInt(),
            cardBg = 0xFF1A1D23.toInt(),
            cardBorder = 0xFF262932.toInt(),
            title = 0xFFECEEF1.toInt(),
            subtitle = 0xFFA6ABB5.toInt(),
            mono = 0xFFDCE0E6.toInt(),
            muted = 0xFF7E8591.toInt(),
            toneOk = 0xFF7DD49A.toInt() to 0xFF152A1F.toInt(),
            toneBad = 0xFFFF8782.toInt() to 0xFF2C1A1B.toInt(),
            toneWarn = 0xFFF0B265.toInt() to 0xFF2D2419.toInt(),
            toneInfo = 0xFF7BB7FF.toInt() to 0xFF15243A.toInt(),
            toneNeutral = 0xFFA6ABB5.toInt() to 0xFF222630.toInt(),
            toneAccent = 0xFF7BFFE3.toInt() to 0xFF103039.toInt(),
        )
    }
}

/**
 * Animated halo: 3 concentric stroke circles that emanate from the
 * view's center, each with a 1/3-cycle phase offset. Used behind the
 * hero brand chip to sell the "scanning device" feel while
 * [DeviceIntelligence.collect] is in flight.
 *
 * Driven by a single [ValueAnimator] that loops a `phase` 0 → 1 over
 * [cycleMs] ms; on each frame we draw 3 rings at radii proportional to
 * `(phase + i/3) % 1`, with their alpha fading from opaque at radius
 * 0 to transparent at the max radius. Cheap (one [Paint], one
 * `invalidate()` per frame, no allocations in [onDraw]) and self-stops
 * via [stop] when the collect finishes.
 */
internal class HaloView(context: Context) : View(context) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP,
            1.4f,
            context.resources.displayMetrics,
        )
    }

    private var ringColor: Int = Color.WHITE
    private var phase: Float = 0f
    private var animator: ValueAnimator? = null

    /** How long one full pulse cycle takes. */
    var cycleMs: Long = 1800L

    /** Starts the looping pulse with rings tinted [color]. Idempotent. */
    fun start(color: Int) {
        ringColor = color
        if (animator?.isStarted == true) {
            invalidate()
            return
        }
        animator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = cycleMs
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener {
                phase = it.animatedValue as Float
                invalidate()
            }
            start()
        }
        animate().alpha(1f).setDuration(180).start()
    }

    /** Cancels the loop and fades the view out so the rings don't linger. */
    fun stop() {
        animator?.cancel()
        animator = null
        animate().alpha(0f).setDuration(180).withEndAction {
            phase = 0f
            invalidate()
        }.start()
    }

    override fun onDetachedFromWindow() {
        animator?.cancel()
        animator = null
        super.onDetachedFromWindow()
    }

    override fun onDraw(canvas: Canvas) {
        if (animator == null && phase == 0f) return
        val cx = width / 2f
        val cy = height / 2f
        val maxR = (min(width, height) / 2f) - paint.strokeWidth
        if (maxR <= 0) return
        val baseRgb = ringColor and 0x00FFFFFF
        for (i in 0 until 3) {
            val p = ((phase + i / 3f) % 1f)
            val r = p * maxR
            // Alpha goes 200 → 0 as the ring expands, so older rings
            // soften without ever quite hitting zero in the middle of
            // the sweep.
            val a = ((1f - p) * 200f).toInt().coerceIn(0, 255)
            paint.color = baseRgb or (a shl 24)
            canvas.drawCircle(cx, cy, r, paint)
        }
    }
}

/**
 * Minimal wrapping row container. Children are laid out left-to-right
 * with [horizontalSpacing] between them and wrap to a new line, with
 * [verticalSpacing] between lines, whenever the next child would
 * exceed the parent's width.
 *
 * No support for child margins / weights — children get
 * `WRAP_CONTENT` measurement and are placed in declaration order.
 * Sized as a tiny inline ViewGroup precisely so the sample stays
 * dependency-free (no AndroidX `FlexboxLayout` / `Flow` helper).
 */
internal class FlowLayout(context: Context) : ViewGroup(context) {

    var horizontalSpacing: Int = 0
    var verticalSpacing: Int = 0

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val widthSize = MeasureSpec.getSize(widthMeasureSpec) - paddingLeft - paddingRight
        val childWidthSpec = MeasureSpec.makeMeasureSpec(widthSize, MeasureSpec.AT_MOST)
        val childHeightSpec = MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED)

        var lineWidth = 0
        var lineHeight = 0
        var totalHeight = 0
        var maxLineWidth = 0
        var firstOnLine = true

        for (i in 0 until childCount) {
            val child = getChildAt(i)
            if (child.visibility == GONE) continue
            child.measure(childWidthSpec, childHeightSpec)
            val cw = child.measuredWidth
            val ch = child.measuredHeight

            val needed = if (firstOnLine) cw else lineWidth + horizontalSpacing + cw
            if (needed > widthSize && !firstOnLine) {
                maxLineWidth = max(maxLineWidth, lineWidth)
                totalHeight += lineHeight + verticalSpacing
                lineWidth = cw
                lineHeight = ch
                firstOnLine = false
            } else {
                lineWidth = needed
                lineHeight = max(lineHeight, ch)
                firstOnLine = false
            }
        }
        maxLineWidth = max(maxLineWidth, lineWidth)
        totalHeight += lineHeight

        val measuredW = resolveSize(maxLineWidth + paddingLeft + paddingRight, widthMeasureSpec)
        val measuredH = resolveSize(totalHeight + paddingTop + paddingBottom, heightMeasureSpec)
        setMeasuredDimension(measuredW, measuredH)
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        val widthSize = r - l - paddingLeft - paddingRight
        var x = paddingLeft
        var y = paddingTop
        var lineHeight = 0
        var firstOnLine = true

        for (i in 0 until childCount) {
            val child = getChildAt(i)
            if (child.visibility == GONE) continue
            val cw = child.measuredWidth
            val ch = child.measuredHeight
            val needed = if (firstOnLine) cw else (x - paddingLeft) + horizontalSpacing + cw
            if (needed > widthSize && !firstOnLine) {
                x = paddingLeft
                y += lineHeight + verticalSpacing
                lineHeight = 0
                firstOnLine = true
            }
            if (!firstOnLine) x += horizontalSpacing
            child.layout(x, y, x + cw, y + ch)
            x += cw
            lineHeight = max(lineHeight, ch)
            firstOnLine = false
        }
    }
}
