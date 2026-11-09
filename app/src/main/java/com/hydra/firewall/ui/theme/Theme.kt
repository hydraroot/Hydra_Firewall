package com.hydra.firewall.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hydra.firewall.AppVisualTheme

val LocalHydraVisualTheme = staticCompositionLocalOf { AppVisualTheme.NEON_TECH }

private data class HydraPalette(
    val primary: Color,
    val onPrimary: Color,
    val primaryContainer: Color,
    val onPrimaryContainer: Color,
    val secondary: Color,
    val onSecondary: Color,
    val secondaryContainer: Color,
    val onSecondaryContainer: Color,
    val tertiary: Color,
    val onTertiary: Color,
    val background: Color,
    val onBackground: Color,
    val surface: Color,
    val onSurface: Color,
    val surfaceVariant: Color,
    val onSurfaceVariant: Color,
    val outline: Color,
    val outlineVariant: Color,
    val error: Color,
    val onError: Color
)

private fun paletteFor(theme: AppVisualTheme, dark: Boolean): HydraPalette {
    return when (theme) {
        AppVisualTheme.NEON_TECH -> if (dark) HydraPalette(
            Color(0xFF00DDF5), Color(0xFF00252B), Color(0xFF073B48), Color(0xFFB9F5FF),
            Color(0xFF32D6C8), Color(0xFF002B29), Color(0xFF06443F), Color(0xFFB0F2E9),
            Color(0xFF63CFFF), Color(0xFF002B3D), Color(0xFF050D16), Color(0xFFE5F8FC),
            Color(0xFF0A1722), Color(0xFFE5F8FC), Color(0xFF102432), Color(0xFFA6C5CF),
            Color(0xFF286071), Color(0xFF1A3C4A), Color(0xFFFF647C), Color(0xFF39000B)
        ) else HydraPalette(
            Color(0xFF006D7D), Color.White, Color(0xFFB6F2FA), Color(0xFF001F25),
            Color(0xFF007F75), Color.White, Color(0xFFB4F0E8), Color(0xFF00201D),
            Color(0xFF006A99), Color.White, Color(0xFFF3FAFC), Color(0xFF101D24),
            Color.White, Color(0xFF101D24), Color(0xFFE2F1F5), Color(0xFF405B64),
            Color(0xFF7899A3), Color(0xFFBDD1D8), Color(0xFFBA1A35), Color.White
        )

        AppVisualTheme.DARK_PREMIUM -> if (dark) HydraPalette(
            Color(0xFFC2A7FF), Color(0xFF26134F), Color(0xFF493477), Color(0xFFEBDDFF),
            Color(0xFFE0B9F5), Color(0xFF351642), Color(0xFF51265F), Color(0xFFF7D8FF),
            Color(0xFF9BC8FF), Color(0xFF082C55), Color(0xFF101019), Color(0xFFF1EFF8),
            Color(0xFF1A1A27), Color(0xFFF1EFF8), Color(0xFF29283A), Color(0xFFC5C1D6),
            Color(0xFF69657D), Color(0xFF3A394D), Color(0xFFFF718A), Color(0xFF410014)
        ) else HydraPalette(
            Color(0xFF6546A8), Color.White, Color(0xFFEBDDFF), Color(0xFF241044),
            Color(0xFF80518D), Color.White, Color(0xFFF5DDF8), Color(0xFF30113A),
            Color(0xFF356A9F), Color.White, Color(0xFFF8F6FC), Color(0xFF201B2A),
            Color(0xFFFFFFFF), Color(0xFF201B2A), Color(0xFFEDE9F5), Color(0xFF514A60),
            Color(0xFF898096), Color(0xFFD2C9DF), Color(0xFFBA1A35), Color.White
        )

        AppVisualTheme.LIGHT_MODERN -> if (dark) HydraPalette(
            Color(0xFF8CB4FF), Color(0xFF09285D), Color(0xFF23477E), Color(0xFFD9E5FF),
            Color(0xFF7DD6C8), Color(0xFF003A33), Color(0xFF15554C), Color(0xFFC3F3E9),
            Color(0xFFD0B8FF), Color(0xFF32116B), Color(0xFF0D1422), Color(0xFFEAF0FA),
            Color(0xFF151F31), Color(0xFFEAF0FA), Color(0xFF222F45), Color(0xFFB7C4D9),
            Color(0xFF536782), Color(0xFF34465F), Color(0xFFFF718A), Color(0xFF410014)
        ) else HydraPalette(
            Color(0xFF2563EB), Color.White, Color(0xFFDCE8FF), Color(0xFF102A60),
            Color(0xFF0F766E), Color.White, Color(0xFFD1F3EC), Color(0xFF063B35),
            Color(0xFF7048C8), Color.White, Color(0xFFF6F8FC), Color(0xFF172033),
            Color.White, Color(0xFF172033), Color(0xFFE9EEF6), Color(0xFF46536A),
            Color(0xFF8795A9), Color(0xFFD3DBE7), Color(0xFFBA1A35), Color.White
        )

        AppVisualTheme.CYBER_ORANGE -> if (dark) HydraPalette(
            Color(0xFFFFA45B), Color(0xFF4A1E00), Color(0xFF713400), Color(0xFFFFDCC2),
            Color(0xFFFFC66D), Color(0xFF3D2A00), Color(0xFF594000), Color(0xFFFFE7AD),
            Color(0xFFFF806B), Color(0xFF4A1008), Color(0xFF120F0D), Color(0xFFF8EEE7),
            Color(0xFF211A16), Color(0xFFF8EEE7), Color(0xFF30251E), Color(0xFFD6BBA8),
            Color(0xFF80624D), Color(0xFF4C392C), Color(0xFFFF7468), Color(0xFF490900)
        ) else HydraPalette(
            Color(0xFFB94F00), Color.White, Color(0xFFFFDCC2), Color(0xFF3D1800),
            Color(0xFF8A5B00), Color.White, Color(0xFFFFE7AD), Color(0xFF2C1D00),
            Color(0xFFB93825), Color.White, Color(0xFFFFF8F1), Color(0xFF281A13),
            Color.White, Color(0xFF281A13), Color(0xFFF5E9DE), Color(0xFF594536),
            Color(0xFF987B67), Color(0xFFE3CDBB), Color(0xFFBA1A35), Color.White
        )

        AppVisualTheme.MATERIAL_MODERN -> if (dark) HydraPalette(
            Color(0xFFADC6FF), Color(0xFF082E68), Color(0xFF284A82), Color(0xFFD9E2FF),
            Color(0xFFB8C8E8), Color(0xFF253550), Color(0xFF3B4C69), Color(0xFFDDE6FF),
            Color(0xFF82D5C8), Color(0xFF003A33), Color(0xFF10151F), Color(0xFFE5EAF4),
            Color(0xFF191F2B), Color(0xFFE5EAF4), Color(0xFF252D3B), Color(0xFFC1C9D8),
            Color(0xFF68758A), Color(0xFF3B4555), Color(0xFFFF718A), Color(0xFF410014)
        ) else HydraPalette(
            Color(0xFF315FAF), Color.White, Color(0xFFDCE5FF), Color(0xFF102D63),
            Color(0xFF536783), Color.White, Color(0xFFDDE6F6), Color(0xFF17283E),
            Color(0xFF006B60), Color.White, Color(0xFFF5F7FB), Color(0xFF171D29),
            Color.White, Color(0xFF171D29), Color(0xFFE9EDF5), Color(0xFF465166),
            Color(0xFF8792A5), Color(0xFFD2D9E5), Color(0xFFBA1A35), Color.White
        )

        AppVisualTheme.GLASS_GREEN -> if (dark) HydraPalette(
            Color(0xFF59E4AE), Color(0xFF003A29), Color(0xFF07543B), Color(0xFFB7F7DC),
            Color(0xFF8BD7B7), Color(0xFF123D2D), Color(0xFF205640), Color(0xFFD0F2E0),
            Color(0xFF77D9E9), Color(0xFF003A43), Color(0xFF061510), Color(0xFFE4F8EC),
            Color(0xFF0D2119), Color(0xFFE4F8EC), Color(0xFF153629), Color(0xFFB6D8C6),
            Color(0xFF477A63), Color(0xFF254B39), Color(0xFFFF718A), Color(0xFF410014)
        ) else HydraPalette(
            Color(0xFF087B50), Color.White, Color(0xFFC8F3DE), Color(0xFF003B25),
            Color(0xFF337D60), Color.White, Color(0xFFD8F0E4), Color(0xFF123D2A),
            Color(0xFF087184), Color.White, Color(0xFFF1FAF4), Color(0xFF14271D),
            Color(0xFFFFFFFF), Color(0xFF14271D), Color(0xFFE0F1E6), Color(0xFF405B49),
            Color(0xFF809C89), Color(0xFFC8DBCD), Color(0xFFBA1A35), Color.White
        )
    }
}

private fun toColorScheme(p: HydraPalette, dark: Boolean) = if (dark) {
    darkColorScheme(
        primary = p.primary, onPrimary = p.onPrimary,
        primaryContainer = p.primaryContainer, onPrimaryContainer = p.onPrimaryContainer,
        secondary = p.secondary, onSecondary = p.onSecondary,
        secondaryContainer = p.secondaryContainer, onSecondaryContainer = p.onSecondaryContainer,
        tertiary = p.tertiary, onTertiary = p.onTertiary,
        background = p.background, onBackground = p.onBackground,
        surface = p.surface, onSurface = p.onSurface,
        surfaceVariant = p.surfaceVariant, onSurfaceVariant = p.onSurfaceVariant,
        outline = p.outline, outlineVariant = p.outlineVariant,
        error = p.error, onError = p.onError,
        surfaceTint = p.primary
    )
} else {
    lightColorScheme(
        primary = p.primary, onPrimary = p.onPrimary,
        primaryContainer = p.primaryContainer, onPrimaryContainer = p.onPrimaryContainer,
        secondary = p.secondary, onSecondary = p.onSecondary,
        secondaryContainer = p.secondaryContainer, onSecondaryContainer = p.onSecondaryContainer,
        tertiary = p.tertiary, onTertiary = p.onTertiary,
        background = p.background, onBackground = p.onBackground,
        surface = p.surface, onSurface = p.onSurface,
        surfaceVariant = p.surfaceVariant, onSurfaceVariant = p.onSurfaceVariant,
        outline = p.outline, outlineVariant = p.outlineVariant,
        error = p.error, onError = p.onError,
        surfaceTint = p.primary
    )
}

private val HydraShapes = Shapes(
    extraSmall = androidx.compose.foundation.shape.RoundedCornerShape(8.dp),
    small = androidx.compose.foundation.shape.RoundedCornerShape(12.dp),
    medium = androidx.compose.foundation.shape.RoundedCornerShape(18.dp),
    large = androidx.compose.foundation.shape.RoundedCornerShape(22.dp),
    extraLarge = androidx.compose.foundation.shape.RoundedCornerShape(28.dp)
)

private val HydraTypography = Typography(
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

/** Shared visual system; changing a palette never changes VPN or firewall behavior. */
@Composable
fun FirewallLocalTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    visualTheme: AppVisualTheme = AppVisualTheme.NEON_TECH,
    content: @Composable () -> Unit
) {
    CompositionLocalProvider(LocalHydraVisualTheme provides visualTheme) {
        MaterialTheme(
            colorScheme = toColorScheme(paletteFor(visualTheme, darkTheme), darkTheme),
            typography = HydraTypography,
            shapes = HydraShapes,
            content = content
        )
    }
}
