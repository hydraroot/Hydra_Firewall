package com.hydra.firewall

import android.Manifest
import com.hydra.firewall.ui.theme.HydraCard
import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.os.Bundle
import android.os.Process
import android.os.Handler
import android.os.Looper
import android.widget.ImageView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.Canvas
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.hydra.firewall.ui.theme.FirewallLocalTheme
import com.hydra.firewall.security.AppIntegrity
import com.hydra.firewall.security.ProtectionStatus
import com.hydra.firewall.vpn.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.Locale

@Composable
internal fun SettingSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean = true,
    onCheckedChange: (Boolean)->Unit
) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)).padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement=Arrangement.SpaceBetween, verticalAlignment=Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f).padding(end=8.dp)) {
            Text(title, color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant)
            Text(subtitle, style=MaterialTheme.typography.bodySmall)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange, enabled = enabled)
    }
}

@Composable
internal fun AppIcon(app: AppEntry?, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    AndroidView(
        modifier = modifier,
        factory = { ImageView(it).apply { scaleType = ImageView.ScaleType.CENTER_INSIDE } },
        update = { view ->
            view.setImageDrawable(app?.let { runCatching { context.packageManager.getApplicationIcon(it.packageName) }.getOrNull() })
        }
    )
}

@Composable
internal fun HydraHorizontalRow(
    modifier: Modifier = Modifier,
    horizontalArrangement: Arrangement.Horizontal = Arrangement.Start,
    content: @Composable RowScope.() -> Unit
) {
    val scrollState = rememberScrollState()
    val darkMode = MaterialTheme.colorScheme.background.luminance() < 0.5f
    Box(modifier = modifier) {
        Row(
            Modifier.fillMaxWidth().horizontalScroll(scrollState),
            horizontalArrangement = horizontalArrangement,
            verticalAlignment = Alignment.CenterVertically,
            content = content
        )
        if (scrollState.maxValue > 0 && scrollState.value > 0) {
            Text("◀", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = if (darkMode) Color.White else Color.Black,
                modifier = Modifier.align(Alignment.CenterStart).padding(start = 2.dp))
        }
        if (scrollState.maxValue > 0 && scrollState.value < scrollState.maxValue) {
            Text("▶", fontSize = 14.sp, fontWeight = FontWeight.Bold, color = if (darkMode) Color.White else Color.Black,
                modifier = Modifier.align(Alignment.CenterEnd).padding(end = 2.dp))
        }
    }
}

@Composable
internal fun ThemeOptionCard(
    title: String,
    accent: Color,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        onClick = onClick,
        modifier = modifier.height(60.dp).shadow(if (selected) 3.dp else 1.dp, RoundedCornerShape(18.dp), clip = false),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surface
        ),
        border = androidx.compose.foundation.BorderStroke(
            if (selected) 1.5.dp else 0.8.dp,
            if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline.copy(alpha = 0.45f)
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = if (selected) 2.dp else 0.dp)
    ) {
        Row(
            Modifier.fillMaxSize().padding(horizontal = 12.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(
                Modifier.size(15.dp).clip(CircleShape).background(accent)
                    .border(1.dp, MaterialTheme.colorScheme.onSurface.copy(alpha = 0.18f), CircleShape)
            )
            Text(
                title,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.labelMedium,
                color = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurface,
                maxLines = 1,
                softWrap = false
            )
            if (selected) {
                Text("✓", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold, fontSize = 15.sp)
            }
        }
    }
}

@Composable
internal fun HydraChoiceButton(
    selected: Boolean,
    label: String,
    selectedColor: Color,
    selectedLabelColor: Color = Color.Unspecified,
    unselectedLabelColor: Color = MaterialTheme.colorScheme.onSurface,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    fontSize: TextUnit = 11.sp
) {
    // Detect Hydra's actual rendered theme. The app supports a manual dark/light
    // setting, so Android system theme is not sufficient here.
    val darkMode = MaterialTheme.colorScheme.background.luminance() < 0.5f
    val background = if (selected) selectedColor else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
    val textColor = if (selected) {
        val blockedLabel = label.equals("Bloqueadas", true) || label.equals("Blocked", true)
        when {
            blockedLabel -> if (darkMode) Color.White else Color.Black
            selectedLabelColor != Color.Unspecified -> selectedLabelColor
            selectedColor.luminance() < 0.50f -> Color.White
            else -> Color(0xFF201A23)
        }
    } else {
        MaterialTheme.colorScheme.onSurfaceVariant
    }
    Box(
        modifier = modifier
            .height(26.dp)
            .clip(RoundedCornerShape(50))
            .background(background)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = label,
            color = textColor,
            fontSize = fontSize,
            maxLines = 1,
            softWrap = false,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
    }
}

@Composable
internal fun RuleModePill(modifier: Modifier, label: String, active: Boolean, activeColor: Color, onClick: () -> Unit) {
    Box(
        modifier
            .height(34.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(if (active) activeColor.copy(alpha = 0.18f) else MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Text(
            if (active && label.length > 1) "$label ✓" else label,
            fontSize = 11.sp, fontWeight = FontWeight.Medium, maxLines = 1,
            color = if (active) activeColor else MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

internal data class NavGroup(val id: String, val glyph: Int, val tabs: List<MainTab>)

/** Tiny vector icons for the bottom bar (drawn, so no icon library is needed). */
@Composable
internal fun NavGlyph(kind: Int, color: Color) {
    Canvas(Modifier.size(24.dp)) {
        val s = size.minDimension / 24f
        val st = Stroke(width = 2f * s, cap = androidx.compose.ui.graphics.StrokeCap.Round, join = androidx.compose.ui.graphics.StrokeJoin.Round)
        val path = androidx.compose.ui.graphics.Path()
        when (kind) {
            0 -> {
                path.moveTo(3f * s, 11f * s); path.lineTo(12f * s, 4f * s); path.lineTo(21f * s, 11f * s)
                path.moveTo(5f * s, 10f * s); path.lineTo(5f * s, 20f * s); path.lineTo(19f * s, 20f * s); path.lineTo(19f * s, 10f * s)
                drawPath(path, color, style = st)
            }
            1 -> listOf(4f to 4f, 14f to 4f, 4f to 14f, 14f to 14f).forEach { (x, y) ->
                drawRoundRect(
                    color, topLeft = androidx.compose.ui.geometry.Offset(x * s, y * s),
                    size = androidx.compose.ui.geometry.Size(6f * s, 6f * s),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(1.5f * s), style = st
                )
            }
            2 -> {
                path.moveTo(2f * s, 12f * s); path.lineTo(7f * s, 12f * s); path.lineTo(10f * s, 5f * s)
                path.lineTo(14f * s, 19f * s); path.lineTo(17f * s, 12f * s); path.lineTo(22f * s, 12f * s)
                drawPath(path, color, style = st)
            }
            3 -> {
                path.moveTo(12f * s, 3f * s); path.lineTo(20f * s, 6f * s); path.lineTo(20f * s, 12f * s)
                path.cubicTo(20f * s, 17f * s, 16f * s, 20f * s, 12f * s, 21f * s)
                path.cubicTo(8f * s, 20f * s, 4f * s, 17f * s, 4f * s, 12f * s)
                path.lineTo(4f * s, 6f * s); path.close()
                drawPath(path, color, style = st)
            }
            else -> listOf(5f, 12f, 19f).forEach { x ->
                drawCircle(color, radius = 1.8f * s, center = androidx.compose.ui.geometry.Offset(x * s, 12f * s))
            }
        }
    }
}

@Composable
internal fun SettingSwitchCard(title: String, subtitle: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    HydraCard(Modifier.fillMaxWidth().padding(vertical = 4.dp), shape = RoundedCornerShape(20.dp)) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 13.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).padding(end = 8.dp)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked, onCheckedChange)
        }
    }
}

@Composable
internal fun SettingsBlockTitle(text: String) {
    Spacer(Modifier.height(19.dp))
    Row(
        Modifier.fillMaxWidth().padding(bottom = 7.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier.size(width = 4.dp, height = 21.dp)
                .clip(RoundedCornerShape(50))
                .background(MaterialTheme.colorScheme.primary)
        )
        Spacer(Modifier.width(9.dp))
        Text(
            text,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
    HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.28f))
    Spacer(Modifier.height(4.dp))
}

@Composable
internal fun HomeStatTile(modifier: Modifier, value: String, label: String) {
    HydraCard(modifier, shape = RoundedCornerShape(19.dp)) {
        Column(Modifier.fillMaxWidth().padding(14.dp)) {
            Text(value, fontWeight = FontWeight.Bold, fontSize = 21.sp, maxLines = 1)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
        }
    }
}
