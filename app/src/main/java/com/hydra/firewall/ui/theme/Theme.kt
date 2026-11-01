package com.hydra.firewall.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

// Modern palette (violet accent, deep neutral surfaces, softer corners). Colors only: no behavior change.
private val DarkColors = darkColorScheme(
    primary = Color(0xFFA78BFA),
    onPrimary = Color(0xFF1A0B3D),
    primaryContainer = Color(0xFF3B2A6E),
    onPrimaryContainer = Color(0xFFE9E1FF),
    secondary = Color(0xFFC4B9E0),
    background = Color(0xFF121217),
    onBackground = Color(0xFFF3F0FF),
    surface = Color(0xFF1B1B22),
    onSurface = Color(0xFFF3F0FF),
    surfaceVariant = Color(0xFF23232B),
    onSurfaceVariant = Color(0xFFB9B5C9),
    outline = Color(0xFF4A4A57),
    error = Color(0xFFF87171)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF6D3FE0),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE9E1FF),
    onPrimaryContainer = Color(0xFF241A34),
    secondary = Color(0xFF5B4B8A),
    background = Color(0xFFF6F4FB),
    onBackground = Color(0xFF1B1B22),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF1B1B22),
    surfaceVariant = Color(0xFFEDE9F7),
    onSurfaceVariant = Color(0xFF4F4A63),
    outline = Color(0xFF8A84A0),
    error = Color(0xFFB3261E)
)

private val ModernShapes = androidx.compose.material3.Shapes(
    extraSmall = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
    small = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
    medium = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
    large = androidx.compose.foundation.shape.RoundedCornerShape(24.dp),
    extraLarge = androidx.compose.foundation.shape.RoundedCornerShape(28.dp)
)

private val CompactTypography = Typography(
    titleLarge = TextStyle(fontWeight = FontWeight.Medium, fontSize = 21.sp, lineHeight = 27.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.Medium, fontSize = 15.sp, lineHeight = 21.sp),
    titleSmall = TextStyle(fontWeight = FontWeight.Medium, fontSize = 13.sp, lineHeight = 18.sp),
    bodyLarge = TextStyle(fontSize = 15.sp, lineHeight = 22.sp),
    bodyMedium = TextStyle(fontSize = 13.sp, lineHeight = 19.sp),
    bodySmall = TextStyle(fontSize = 11.sp, lineHeight = 16.sp),
    labelLarge = TextStyle(fontWeight = FontWeight.Medium, fontSize = 13.sp, lineHeight = 18.sp),
    labelMedium = TextStyle(fontWeight = FontWeight.Medium, fontSize = 11.sp, lineHeight = 16.sp),
    labelSmall = TextStyle(fontWeight = FontWeight.Medium, fontSize = 10.sp, lineHeight = 14.sp)
)

@Composable
fun FirewallLocalTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Material You (dynamic color) derives its palette from the device
    // wallpaper. Hydra lets the user pick Light/Dark/System manually, and
    // every screen (dialog surfaces, choice buttons, etc.) was hand-tuned
    // against the fixed DarkColors/LightColors palettes below. Keep this
    // false: a wallpaper-derived scheme can silently break that contrast
    // even though `darkTheme` itself is computed correctly, which is what
    // forced FIX50-FIX57 to patch per-dialog colors one screen at a time
    // instead of fixing it once here. Only opt back into dynamic color if
    // every screen's colors are re-audited against arbitrary wallpapers.
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }

    MaterialTheme(colorScheme = colorScheme, typography = CompactTypography, shapes = ModernShapes, content = content)
}
