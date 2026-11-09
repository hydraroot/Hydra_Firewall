package com.hydra.firewall.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Hydra Neon Tech palette. Semantic status colors (allow/block/warning) remain separate. */
private val NeonDarkColors = darkColorScheme(
    primary = Color(0xFF00DDF5),
    onPrimary = Color(0xFF00252B),
    primaryContainer = Color(0xFF073B48),
    onPrimaryContainer = Color(0xFFB9F5FF),
    secondary = Color(0xFF32D6C8),
    onSecondary = Color(0xFF002B29),
    secondaryContainer = Color(0xFF06443F),
    onSecondaryContainer = Color(0xFFB0F2E9),
    tertiary = Color(0xFF63CFFF),
    onTertiary = Color(0xFF002B3D),
    background = Color(0xFF050D16),
    onBackground = Color(0xFFE5F8FC),
    surface = Color(0xFF0A1722),
    onSurface = Color(0xFFE5F8FC),
    surfaceVariant = Color(0xFF102432),
    onSurfaceVariant = Color(0xFFA6C5CF),
    outline = Color(0xFF286071),
    outlineVariant = Color(0xFF1A3C4A),
    error = Color(0xFFFF647C),
    onError = Color(0xFF39000B),
    surfaceTint = Color(0xFF00DDF5)
)

private val NeonLightColors = lightColorScheme(
    primary = Color(0xFF006D7D),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFB6F2FA),
    onPrimaryContainer = Color(0xFF001F25),
    secondary = Color(0xFF007F75),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFB4F0E8),
    onSecondaryContainer = Color(0xFF00201D),
    tertiary = Color(0xFF006A99),
    onTertiary = Color(0xFFFFFFFF),
    background = Color(0xFFF3FAFC),
    onBackground = Color(0xFF101D24),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF101D24),
    surfaceVariant = Color(0xFFE2F1F5),
    onSurfaceVariant = Color(0xFF405B64),
    outline = Color(0xFF7899A3),
    outlineVariant = Color(0xFFBDD1D8),
    error = Color(0xFFBA1A35),
    onError = Color(0xFFFFFFFF),
    surfaceTint = Color(0xFF006D7D)
)

private val NeonShapes = Shapes(
    extraSmall = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
    small = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
    medium = androidx.compose.foundation.shape.RoundedCornerShape(18.dp),
    large = androidx.compose.foundation.shape.RoundedCornerShape(22.dp),
    extraLarge = androidx.compose.foundation.shape.RoundedCornerShape(28.dp)
)

private val NeonTypography = Typography(
    titleLarge = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 22.sp, lineHeight = 28.sp),
    titleMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp),
    titleSmall = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 14.sp, lineHeight = 19.sp),
    bodyLarge = TextStyle(fontSize = 15.sp, lineHeight = 22.sp),
    bodyMedium = TextStyle(fontSize = 13.sp, lineHeight = 19.sp),
    bodySmall = TextStyle(fontSize = 11.sp, lineHeight = 16.sp),
    labelLarge = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 13.sp, lineHeight = 18.sp),
    labelMedium = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 11.sp, lineHeight = 16.sp),
    labelSmall = TextStyle(fontWeight = FontWeight.SemiBold, fontSize = 10.sp, lineHeight = 14.sp, letterSpacing = 0.35.sp)
)

/** Keeps the existing user-selected light/dark/system preference; only the visual palette changes. */
@Composable
fun FirewallLocalTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) NeonDarkColors else NeonLightColors,
        typography = NeonTypography,
        shapes = NeonShapes,
        content = content
    )
}
