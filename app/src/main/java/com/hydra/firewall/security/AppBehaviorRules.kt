package com.hydra.firewall.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * Permission-based behavior rules for apps that did NOT come from a known store ("sideloaded").
 *
 * These are indications, not proof: many legitimate apps request some of these permissions. They only
 * apply to apps installed outside a known store, and each one is explained in plain language so the user
 * can look into it (Google button) and ignore it if it is fine.
 */
object AppBehaviorRules {
    enum class Level { LOW, MEDIUM, HIGH }

    data class Facts(
        val requested: Set<String>,      // short permission names, e.g. "READ_SMS"
        val bound: Set<String>,          // permissions protecting its services/receivers, e.g. "BIND_ACCESSIBILITY_SERVICE"
        val installer: String?,          // installing package, null = unknown / sideloaded
        val isSystem: Boolean
    )

    data class Indicator(val id: String, val level: Level, val es: String, val en: String)

    private val KNOWN_STORES = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.amazon.venezia", "com.huawei.appmarket",
        "org.fdroid.fdroid", "com.xiaomi.mipicks", "com.heytap.market", "com.oppo.market", "com.vivo.appstore",
        "com.google.android.feedback", "com.aurora.store"
    )

    fun isSideloaded(f: Facts): Boolean = !f.isSystem && (f.installer == null || f.installer !in KNOWN_STORES)

    /** "store", "sideload" or "system": used to label scan results for calibration. */
    fun source(f: Facts): String = when {
        f.isSystem -> "system"
        isSideloaded(f) -> "sideload"
        else -> "store"
    }

    internal fun short(permission: String): String = permission.substringAfterLast('.')

    fun evaluate(f: Facts): List<Indicator> {
        if (!isSideloaded(f)) return emptyList()
        val r = f.requested
        val b = f.bound
        val sms = "READ_SMS" in r || "RECEIVE_SMS" in r
        val overlay = "SYSTEM_ALERT_WINDOW" in r
        val accessibility = "BIND_ACCESSIBILITY_SERVICE" in b
        val listener = "BIND_NOTIFICATION_LISTENER_SERVICE" in b
        val out = ArrayList<Indicator>()
        if (accessibility && (overlay || sms)) out += Indicator(
            "A11Y_OVERLAY_SMS", Level.HIGH,
            "Puede leer lo que ves en pantalla y " + (if (overlay) "dibujar pantallas encima de otras apps" else "leer tus SMS") + ": combinación típica de troyanos bancarios.",
            "It can read your screen and " + (if (overlay) "draw over other apps" else "read your SMS") + ": a typical banking-trojan combination."
        )
        if (listener && sms) out += Indicator(
            "LISTENER_SMS", Level.HIGH,
            "Puede leer tus notificaciones y SMS: así se roban códigos de verificación.",
            "It can read your notifications and SMS: this is how verification codes are stolen."
        )
        if (accessibility && !(overlay || sms)) out += Indicator(
            "A11Y", Level.MEDIUM,
            "Tiene un servicio de accesibilidad: puede ver y controlar la pantalla.",
            "It has an accessibility service: it can see and control the screen."
        )
        if ("BIND_DEVICE_ADMIN" in b) out += Indicator(
            "DEVICE_ADMIN", Level.MEDIUM,
            "Es administrador del dispositivo: puede dificultar que la desinstales.",
            "It is a device administrator: it can make it harder to uninstall."
        )
        if ("REQUEST_INSTALL_PACKAGES" in r) out += Indicator(
            "INSTALLER", Level.MEDIUM,
            "Puede instalar otras apps: un malware puede usarlo para descargar más malware.",
            "It can install other apps: malware can use this to download more malware."
        )
        if (sms && "SEND_SMS" in r) out += Indicator(
            "SMS_RW", Level.MEDIUM,
            "Puede leer y enviar SMS (posible fraude de SMS premium).",
            "It can read and send SMS (possible premium-SMS fraud)."
        )
        if (listener && !sms) out += Indicator(
            "LISTENER", Level.LOW,
            "Puede leer tus notificaciones.",
            "It can read your notifications."
        )
        if ("MANAGE_EXTERNAL_STORAGE" in r) out += Indicator(
            "ALL_FILES", Level.LOW,
            "Pide acceso a todos tus archivos.",
            "It asks for access to all your files."
        )
        if (overlay && !accessibility) out += Indicator(
            "OVERLAY", Level.LOW,
            "Puede dibujar encima de otras apps.",
            "It can draw over other apps."
        )
        return out.sortedByDescending { it.level.ordinal }
    }

    fun worst(list: List<Indicator>): Level? = list.maxByOrNull { it.level.ordinal }?.level

    /** Stable key of a set of indicators (used to remember "ignored"). */
    fun key(list: List<Indicator>): String = list.map { it.id }.sorted().joinToString("|")

    // ---- reading the facts from the device (does I/O: call off the main thread) -------------------------

    @Suppress("DEPRECATION")
    fun factsFor(context: Context, packageName: String): Facts? = runCatching {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS
        val pi = pm.getPackageInfo(packageName, flags)
        val bound = (pi.services.orEmpty().mapNotNull { it.permission } + pi.receivers.orEmpty().mapNotNull { it.permission })
            .map(::short).toSet()
        val requested = pi.requestedPermissions.orEmpty().map(::short).toSet()
        val system = (pi.applicationInfo?.flags ?: 0) and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        Facts(requested, bound, installerOf(context, packageName), system)
    }.getOrNull()

    @Suppress("DEPRECATION")
    fun installerOf(context: Context, packageName: String): String? = runCatching {
        val pm = context.packageManager
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(packageName).installingPackageName
        else pm.getInstallerPackageName(packageName)
    }.getOrNull()
}
