package com.hydra.firewall.ui.theme

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.dp
import com.hydra.firewall.AppVisualTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow

/**
 * Shared surface for Hydra screens. The refinement is deliberately visual-only:
 * it reads the active palette and never changes the content, callbacks or state
 * owned by the screen using the card.
 */
@Composable
fun HydraCard(
    modifier: Modifier = Modifier,
    shape: Shape = RoundedCornerShape(21.dp),
    containerColor: Color? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val visualTheme = LocalHydraVisualTheme.current
    val isGlass = visualTheme == AppVisualTheme.GLASS_GREEN
    val isNeon = visualTheme == AppVisualTheme.NEON_TECH
    val resolvedContainer = containerColor ?: if (isGlass) {
        MaterialTheme.colorScheme.surface.copy(alpha = 0.90f)
    } else {
        MaterialTheme.colorScheme.surface
    }
    val outlineAlpha = when {
        isGlass -> 0.66f
        isNeon -> 0.52f
        else -> 0.38f
    }
    val cardModifier = modifier
        .shadow(
            elevation = if (isNeon || isGlass) 3.dp else 2.dp,
            shape = shape,
            clip = false
        )
        .clip(shape)
    Card(
        modifier = cardModifier,
        shape = shape,
        colors = CardDefaults.cardColors(containerColor = resolvedContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp, pressedElevation = 0.dp),
        border = BorderStroke(
            1.dp,
            MaterialTheme.colorScheme.outline.copy(alpha = outlineAlpha)
        ),
        content = content
    )
}
