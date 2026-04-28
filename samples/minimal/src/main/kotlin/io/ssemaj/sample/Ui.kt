package io.ssemaj.sample

import android.content.Context
import android.content.res.Configuration
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.max

/**
 * Tiny programmatic-UI toolkit for the sample app. Kept self-contained
 * (no AndroidX, no resources) so the sample stays a one-jar
 * smoke-test artifact rather than a full app project.
 *
 * Instantiated once per [android.app.Activity] via [forContext], which
 * picks a light or dark [Palette] based on the current
 * `uiMode` configuration. All colors flow through the palette so the
 * app respects the system theme.
 */
internal class Ui(val palette: Palette) {

    enum class Tone { OK, BAD, WARN, INFO, NEUTRAL }

    private fun tonePair(t: Tone): Pair<Int, Int> = when (t) {
        Tone.OK -> palette.toneOk
        Tone.BAD -> palette.toneBad
        Tone.WARN -> palette.toneWarn
        Tone.INFO -> palette.toneInfo
        Tone.NEUTRAL -> palette.toneNeutral
    }

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

    /** Re-color a hero produced by [heroBanner] to the given tone. */
    fun tintHero(hero: LinearLayout, tone: Tone) {
        (hero.background as GradientDrawable).setColor(tonePair(tone).second)
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
     * Horizontal row that places the [titleText] flush-left and an
     * optional list of [accessories] (typically badges) flush-right.
     * Used for card title bars.
     */
    fun titleRow(
        context: Context,
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
    fun kv(context: Context, key: String, value: String?): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 4) }
        }
        row.addView(
            TextView(context).apply {
                text = key
                textSize = 11.5f
                setTextColor(palette.muted)
                layoutParams = LinearLayout.LayoutParams(
                    dp(context, 132),
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
     * One row in the Findings list: severity pill on the left, then a
     * vertical block of `kind` (mono bold), `subject` (muted), and
     * `message` (subtitle color).
     */
    fun findingRow(
        context: Context,
        severityLabel: String,
        tone: Tone,
        kind: String,
        subject: String?,
        message: String,
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 10) }
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
     * One row in the Detectors list: id (mono), status pill, then
     * `Nms · K finding(s)` on the right.
     */
    fun detectorRow(
        context: Context,
        id: String,
        statusLabel: String,
        statusTone: Tone,
        rightLabel: String,
    ): LinearLayout {
        val row = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { topMargin = dp(context, 8) }
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
        )
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
