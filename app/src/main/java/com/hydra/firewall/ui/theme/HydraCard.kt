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

/** Shared theme-aware card surface used across all Hydra screens. */
@Composable
fun HydraCard(
    modifier: Modifier = Modifier,
    shape: Shape = RoundedCornerShape(18.dp),
    containerColor: Color? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val isGlass = LocalHydraVisualTheme.current == AppVisualTheme.GLASS_GREEN
    val resolvedContainer = containerColor ?: if (isGlass) {
        MaterialTheme.colorScheme.surface.copy(alpha = 0.88f)
    } else {
        MaterialTheme.colorScheme.surface
    }
    Card(
        modifier = modifier,
        shape = shape,
        colors = CardDefaults.cardColors(containerColor = resolvedContainer),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp, pressedElevation = 1.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = if (isGlass) 0.68f else 0.42f)),
        content = content
    )
}
