package tech.thessemaj.deviceintelligence.sample.ui.component

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import tech.thessemaj.deviceintelligence.sample.R
import tech.thessemaj.deviceintelligence.sample.ui.theme.MonoStyle
import tech.thessemaj.deviceintelligence.sample.ui.theme.IntelColors

/**
 * The shared vocabulary every screen is built from.
 *
 * These replace the ~20 view-builder methods the Activity used to carry
 * (`table`, `kvRow`, `checkRow`, `chip`, `note`, `hint`, `subhead`, …). The
 * wording and spacing are deliberately unchanged: the explanatory copy IS the
 * product here, since the point of the testbed is explaining a verdict.
 */

/** A small outlined status chip. */
@Composable
fun Chip(label: String, colour: Color, modifier: Modifier = Modifier) {
    Text(
        text = label,
        color = colour,
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        style = MonoStyle,
        modifier = modifier
            .border(1.dp, colour, RoundedCornerShape(6.dp))
            .padding(horizontal = 9.dp, vertical = 5.dp),
    )
}

/** A boxed paragraph explaining what the reader is looking at. */
@Composable
fun Note(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        color = IntelColors.TextDim,
        fontSize = 13.sp,
        lineHeight = 20.sp,
        modifier = modifier
            .padding(top = 12.dp)
            .fillMaxWidth()
            .background(IntelColors.Card, RoundedCornerShape(10.dp))
            .padding(horizontal = 16.dp, vertical = 14.dp),
    )
}

/** Secondary explanatory line. */
@Composable
fun Hint(text: String, modifier: Modifier = Modifier) {
    Text(
        text = text,
        color = IntelColors.TextDim,
        fontSize = 13.sp,
        lineHeight = 19.sp,
        modifier = modifier.padding(top = 8.dp, bottom = 2.dp),
    )
}

/** A group heading with what the group is for. */
@Composable
fun Subhead(title: String, why: String) {
    Text(
        text = title,
        color = Color.White,
        fontSize = 16.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 20.dp),
    )
    Text(
        text = why,
        color = IntelColors.TextDim,
        fontSize = 13.sp,
        modifier = Modifier.padding(top = 2.dp, bottom = 8.dp),
    )
}

/** A titled group of key/value rows. */
@Composable
fun SectionTable(title: String, content: @Composable () -> Unit) {
    Text(
        text = title,
        color = Color.White,
        fontSize = 15.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 18.dp, bottom = 8.dp),
    )
    Column(
        Modifier
            .fillMaxWidth()
            .background(IntelColors.Card, RoundedCornerShape(12.dp))
            .border(1.dp, IntelColors.Stroke, RoundedCornerShape(12.dp))
            .padding(horizontal = 16.dp, vertical = 10.dp),
    ) { content() }
}

/** key -> value: the row every table here is built from. */
@Composable
fun KeyValueRow(key: String, value: String) {
    Column(Modifier.padding(vertical = 8.dp)) {
        Text(key, color = IntelColors.TextDim, fontSize = 13.sp)
        Text(
            text = value,
            color = Color.White,
            fontSize = 15.sp,
            lineHeight = 21.sp,
            style = MonoStyle,
            modifier = Modifier.padding(top = 2.dp),
        )
    }
}

/** PASS/FAIL, the check name, and the detail when it failed. */
@Composable
fun CheckRow(ok: Boolean, name: String, detail: String) {
    Row(
        Modifier.fillMaxWidth().padding(top = 10.dp, bottom = 4.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Chip(
            stringResource(if (ok) R.string.check_pass else R.string.check_fail),
            if (ok) IntelColors.Green else IntelColors.Red,
        )
        Text(
            text = name,
            color = if (ok) Color.White else IntelColors.Red,
            fontSize = 15.sp,
            lineHeight = 21.sp,
            modifier = Modifier.padding(start = 12.dp),
        )
    }
    if (detail.isNotEmpty()) {
        Text(
            text = detail,
            color = IntelColors.TextDim,
            fontSize = 13.sp,
            lineHeight = 19.sp,
            modifier = Modifier.padding(start = 62.dp, bottom = 6.dp),
        )
    }
}

/**
 * A card surface: the shape every grouped block on every screen uses.
 *
 * [spine] draws a colour bar down the leading edge. Only the signals screen passes
 * one, because only a signal carries a severity — the bar encodes information
 * rather than decorating the card.
 */
@Composable
fun IntelCard(
    modifier: Modifier = Modifier,
    spine: Color? = null,
    content: @Composable () -> Unit,
) {
    val shape = RoundedCornerShape(12.dp)
    Row(
        modifier
            .fillMaxWidth()
            .background(
                // A lighter edge along the top, the way light catches a feather.
                Brush.verticalGradient(
                    0f to IntelColors.CardEdge,
                    0.02f to IntelColors.Card,
                ),
                shape,
            )
            .border(1.dp, IntelColors.Stroke, shape)
            .clip(shape),
    ) {
        if (spine != null) {
            Box(Modifier.width(3.dp).fillMaxHeight().background(spine))
        }
        Column(Modifier.padding(16.dp)) { content() }
    }
}

@Composable
fun VSpace(height: Int) = Spacer(Modifier.height(height.dp))

@Composable
fun HSpace(width: Int) = Spacer(Modifier.width(width.dp))
