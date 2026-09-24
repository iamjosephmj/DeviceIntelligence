package tech.thessemaj.deviceintelligence.sample.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * The testbed palette.
 *
 * Deliberately fixed rather than following the system theme: screenshots of a
 * verdict get pasted into bug reports and compared against each other, so the same
 * result has to render identically on every handset in the matrix.
 *
 * The greys are not neutral. The brand plumage is black that throws indigo and violet
 * where light hits it, so the ground carries a slight blue-violet cast and the
 * accent sits on the same sheen. The three status colours stay strictly semantic —
 * they are the only saturated things on any screen.
 */
object IntelColors {
    /** Base ground: near-black, cooled toward indigo. */
    val Background = Color(0xFF0A0C12)

    /** Top of the plumage wash — where the light catches. */
    val SheenHigh = Color(0xFF141829)

    /** Bottom of the wash. */
    val SheenLow = Color(0xFF08090E)

    val Card = Color(0xFF151A24)

    /** The lit edge along the top of a card, as on the leading edge of a feather. */
    val CardEdge = Color(0xFF2A3142)

    val Stroke = Color(0xFF222836)
    val TextDim = Color(0xFF97A1B2)

    /** Wing-sheen indigo. Actions only. */
    val Accent = Color(0xFF5A63D8)
    val AccentDisabled = Color(0xFF232838)

    /** The eye. Also the warning tone — the eye tone is exactly this colour. */
    val Iris = Color(0xFFE0B84F)

    val Green = Color(0xFF57D9A3)
    val Amber = Color(0xFFE0B84F)
    val Red = Color(0xFFE06C6C)

    /** The mark itself. */
    val Ink = Color(0xFFE6EDF5)
    val InkMuted = Color(0xFF7C8899)
}
