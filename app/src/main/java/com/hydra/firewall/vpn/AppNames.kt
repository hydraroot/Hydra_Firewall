package com.hydra.firewall.vpn

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * Human-readable name for "whatever owns this traffic", so the UI never shows a bare "UID 1234".
 * Order: app label of the package -> label of the app(s) that share the UID -> well-known system UID name ->
 * "App uninstalled" for app UIDs without packages. The technical UID is always kept in parentheses at the end
 * when no real app name is known.
 */
object AppNames {
    @Volatile private var appContext: Context? = null
    private val cache = ConcurrentHashMap<String, String>()

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** Names of Android's fixed system UIDs (below 10000). */
    internal fun systemUidName(uid: Int, english: Boolean): String? = when (uid) {
        0 -> if (english) "Android system (root)" else "Sistema Android (root)"
        1000 -> if (english) "Android system" else "Sistema Android"
        1001 -> if (english) "Phone / radio service" else "Servicio de telefonía"
        1002 -> if (english) "Bluetooth service" else "Servicio Bluetooth"
        1010 -> if (english) "Wi-Fi service" else "Servicio Wi-Fi"
        1013 -> if (english) "Media server" else "Servidor multimedia"
        1020 -> if (english) "Network discovery (mDNS)" else "Descubrimiento de red (mDNS)"
        1021 -> if (english) "Location service (GPS)" else "Servicio de ubicación (GPS)"
        1023 -> if (english) "Media storage" else "Almacenamiento multimedia"
        1051 -> if (english) "Network daemon (netd)" else "Servicio de red (netd)"
        1066 -> if (english) "Android system service" else "Servicio del sistema Android"
        2000 -> if (english) "Android debug shell" else "Shell de depuración (adb)"
        9999 -> if (english) "Unassigned (nobody)" else "Sin asignar (nobody)"
        else -> null
    }

    internal fun fallback(uid: Int, english: Boolean): String = when {
        uid < 0 -> "?"
        systemUidName(uid, english) != null -> "${systemUidName(uid, english)} ($uid)"
        uid < 10000 -> if (english) "System process (UID $uid)" else "Proceso del sistema (UID $uid)"
        else -> if (english) "Unknown or uninstalled app (UID $uid)" else "App desconocida o desinstalada (UID $uid)"
    }

    fun label(uid: Int, packageName: String? = null): String {
        val ctx = appContext ?: return packageName?.takeIf { it.isNotBlank() } ?: (if (uid >= 0) "UID $uid" else "?")
        val key = "$uid|${packageName.orEmpty()}"
        cache[key]?.let { return it }
        val english = runCatching { com.hydra.firewall.AppSettings(ctx).language.isEnglish() }.getOrDefault(false)
        val pm = ctx.packageManager
        fun labelOf(pkg: String): String? = runCatching {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString().takeIf { it.isNotBlank() }
        }.getOrNull()
        var resolved = packageName?.takeIf { it.isNotBlank() }?.let { labelOf(it) }
        if (resolved == null && uid >= 0) {
            val pkgs = runCatching { pm.getPackagesForUid(uid)?.toList().orEmpty() }.getOrDefault(emptyList())
            val first = pkgs.firstNotNullOfOrNull { labelOf(it) }
            if (first != null) resolved = if (pkgs.size > 1) "$first +${pkgs.size - 1}" else first
        }
        val result = resolved ?: packageName?.takeIf { it.isNotBlank() } ?: fallback(uid, english)
        // Only cache real answers: a package installed later should still be picked up.
        if (resolved != null) cache[key] = result
        return result
    }

    /** Forget cached names (after an app is installed, updated or removed). */
    fun invalidate() = cache.clear()
}
