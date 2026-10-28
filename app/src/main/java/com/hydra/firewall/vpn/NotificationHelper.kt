package com.hydra.firewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.os.Build
import androidx.core.app.NotificationCompat
import com.hydra.firewall.AppLanguage
import com.hydra.firewall.AppSettings
import com.hydra.firewall.isEnglish
import com.hydra.firewall.MainActivity
import com.hydra.firewall.security.Severity
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** Notifications for the foreground service, pending access requests and security events. */
object NotificationHelper {
    private const val FOREGROUND_CHANNEL_ID = "firewall_channel"
    private const val FOREGROUND_ID = 1
    private const val ACCESS_REQUEST_CHANNEL_ID = "hydra_access_requests"
    private const val ACCESS_REQUEST_NOTIFICATION_BASE_ID = 9100
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var updateRunnable: Runnable? = null
    @Volatile private var lastAllowed = -1L
    @Volatile private var lastBlocked = -1L

    @Synchronized
    fun init(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // Do NOT cancel current access-request notifications here. This method is
        // called from FirewallVpnService.onCreate(), so clearing the prompt range
        // would erase valid pending requests whenever the VPN service restarts.
        // Only retire the old prompt channel from the pre-queue UI.
        manager.cancel(8999)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.deleteNotificationChannel("firewall_prompt")
            manager.createNotificationChannel(
                NotificationChannel(
                    FOREGROUND_CHANNEL_ID,
                    "Hydra Firewall",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "Estado del Hydra Firewall"
                    setShowBadge(false)
                }
            )
            manager.createNotificationChannel(
                NotificationChannel(
                    ACCESS_REQUEST_CHANNEL_ID,
                    "Hydra access requests",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = if (AppSettings(context).language.isEnglish()) "Pending per-app Internet access requests" else "Solicitudes pendientes de acceso a Internet por aplicación"
                    setShowBadge(true)
                }
            )
        }
    }

    fun buildForegroundNotification(context: Context): Notification {
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        )
        return buildStatusNotification(context, pendingIntent)
    }

    fun startLiveStatus(context: Context) {
        stopLiveStatus()
        lastAllowed = -1L
        lastBlocked = -1L
        val appContext = context.applicationContext
        val runnable = object : Runnable {
            override fun run() {
                updateForeground(appContext)
                val settings = AppSettings(appContext)
                handler.postDelayed(this, if (settings.lowPowerMode) 60_000L else 30_000L)
            }
        }
        updateRunnable = runnable
        handler.post(runnable)
    }

    fun stopLiveStatus() {
        updateRunnable?.let(handler::removeCallbacks)
        updateRunnable = null
    }

    private fun updateForeground(context: Context) {
        val totals = TrafficStatsStore.totals()
        if (totals.allowedBytes == lastAllowed && totals.blockedBytes == lastBlocked) return
        lastAllowed = totals.allowedBytes
        lastBlocked = totals.blockedBytes
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(FOREGROUND_ID, buildForegroundNotification(context))
    }

    private fun buildStatusNotification(context: Context, pendingIntent: PendingIntent): Notification {
        val english = AppSettings(context).language.isEnglish() ||
            (AppSettings(context).language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
        val totals = TrafficStatsStore.totals()
        val active = FirewallVpnService.activeTcpSessions + FirewallVpnService.activeUdpSessions
        val title = if (english) "Hydra Firewall active" else "Hydra Firewall activo"
        val text = if (english) {
            "Blocked ${formatMb(totals.blockedBytes)} MB · Allowed ${formatMb(totals.allowedBytes)} MB · Active $active"
        } else {
            "Bloqueado ${formatMb(totals.blockedBytes)} MB · Permitido ${formatMb(totals.allowedBytes)} MB · Activas $active"
        }
        return NotificationCompat.Builder(context, FOREGROUND_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()
    }

    private fun formatMb(bytes: Long): String = String.format(Locale.US, "%.1f", bytes.toDouble() / (1024.0 * 1024.0))

    private const val SECURITY_CHANNEL_ID = "hydra_security_events"
    private const val QUARANTINE_NOTIFICATION_ID = 20001
    private const val TAMPER_NOTIFICATION_ID = 20002
    private const val THREAT_NOTIFICATION_BASE_ID = 21000
    private val threatNotifyTimes = ConcurrentHashMap<String, Long>()
    private val accessNotificationIds = ConcurrentHashMap<String, Int>()
    private val nextAccessNotificationId = AtomicInteger(ACCESS_REQUEST_NOTIFICATION_BASE_ID)

    private fun ensureSecurityChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                SECURITY_CHANNEL_ID,
                "Hydra Security Center",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = if (AppSettings(context).language.isEnglish()) "New-app quarantine, service tampering and other security alerts" else "Cuarentena de apps nuevas, manipulación del servicio y otras alertas de seguridad"
            }
        )
    }

    /** Persistent notification for one grouped app/UID/network access request.
     * Every unresolved request has its own notification and PendingIntent. */
    fun notifyAccessRequest(context: Context, token: String, packageName: String?, uid: Int, network: NetworkKind, pendingCount: Int, attemptCount: Int = 1) {
        ensureAccessRequestChannel(context)
        val english = AppSettings(context).language.isEnglish() ||
            (AppSettings(context).language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
        val appInfo = packageName?.let { pkg ->
            runCatching { context.packageManager.getApplicationInfo(pkg, 0) }.getOrNull()
        }
        val label = appInfo?.let {
            runCatching { context.packageManager.getApplicationLabel(it).toString() }.getOrNull()
        }?.takeIf { it.isNotBlank() }
            ?: packageName?.takeIf { it.isNotBlank() }
            ?: if (english) "Unknown application" else "Aplicación desconocida"
        val notificationId = accessRequestNotificationId(token)
        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            com.hydra.firewall.AppAccessRequestActivity.buildIntent(context, token),
            PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        )
        val grouped = if (attemptCount > 1) {
            if (english) "$attemptCount grouped attempts" else "$attemptCount intentos agrupados"
        } else {
            if (english) "1 connection" else "1 conexión"
        }
        val pending = if (pendingCount > 1) {
            if (english) " · $pendingCount pending" else " · $pendingCount pendientes"
        } else ""
        val text = "${network.displayName} · $grouped$pending"
        val builder = NotificationCompat.Builder(context, ACCESS_REQUEST_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(if (english) "Access request: $label" else "Solicitud de acceso: $label")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                if (english) "Tap to review $label. This request stays pending until you choose a policy."
                else "Tocá para revisar $label. Esta solicitud queda pendiente hasta que elijas una política."
            ))
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
        appInfo?.let { info ->
            val drawable = runCatching { info.loadIcon(context.packageManager) }.getOrNull()
            drawable?.let { builder.setLargeIcon(drawableToBitmap(it)) }
        }
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(notificationId, builder.build())
    }

    private fun drawableToBitmap(drawable: Drawable): Bitmap {
        val width = drawable.intrinsicWidth.takeIf { it > 0 } ?: 64
        val height = drawable.intrinsicHeight.takeIf { it > 0 } ?: 64
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        return bitmap
    }

    fun clearAccessRequestNotification(context: Context, token: String) {
        (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .cancel(accessRequestNotificationId(token))
        accessNotificationIds.remove(token)
    }

    fun clearAccessRequestNotifications(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(8999)
        for (id in 9000..14150) manager.cancel(id)
    }

    private fun accessRequestNotificationId(token: String): Int {
        // Allocate unique in-process ids so two different UUID tokens cannot
        // accidentally overwrite each other's pending prompt notification.
        return accessNotificationIds[token] ?: synchronized(accessNotificationIds) {
            accessNotificationIds[token] ?: run {
                var candidate = nextAccessNotificationId.getAndIncrement()
                if (candidate >= ACCESS_REQUEST_NOTIFICATION_BASE_ID + 5000) {
                    nextAccessNotificationId.set(ACCESS_REQUEST_NOTIFICATION_BASE_ID + 1)
                    candidate = ACCESS_REQUEST_NOTIFICATION_BASE_ID
                }
                while (accessNotificationIds.containsValue(candidate)) {
                    candidate = nextAccessNotificationId.getAndIncrement()
                    if (candidate >= ACCESS_REQUEST_NOTIFICATION_BASE_ID + 5000) {
                        nextAccessNotificationId.set(ACCESS_REQUEST_NOTIFICATION_BASE_ID + 1)
                        candidate = ACCESS_REQUEST_NOTIFICATION_BASE_ID
                    }
                }
                accessNotificationIds[token] = candidate
                candidate
            }
        }
    }

    private fun ensureAccessRequestChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                ACCESS_REQUEST_CHANNEL_ID,
                "Hydra access requests",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = if (AppSettings(context).language.isEnglish()) "Pending per-app Internet access requests" else "Solicitudes pendientes de acceso a Internet por aplicación"
                setShowBadge(true)
            }
        )
    }

    /** New app installed while quarantine-on-install is enabled: it's already
     *  blocked, this just tells the person there's something waiting for review. */
    fun notifyQuarantine(context: Context, packageName: String) {
        ensureSecurityChannel(context)
        val english = AppSettings(context).language.isEnglish() ||
            (AppSettings(context).language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
        val label = runCatching {
            context.packageManager.getApplicationInfo(packageName, 0).loadLabel(context.packageManager).toString()
        }.getOrDefault(packageName)
        val pendingIntent = PendingIntent.getActivity(
            context, 1,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        )
        val notification = NotificationCompat.Builder(context, SECURITY_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(if (english) "New app quarantined" else "Nueva app en cuarentena")
            .setContentText(
                if (english) "$label is blocked until you review it in Security Center"
                else "$label está bloqueada hasta que la revisés en el Centro de Seguridad"
            )
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(QUARANTINE_NOTIFICATION_ID, notification)
    }

    /** The VPN service stopped without a matching intentional-stop marker. */
    fun notifyTamper(context: Context) {
        ensureSecurityChannel(context)
        val english = AppSettings(context).language.isEnglish() ||
            (AppSettings(context).language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
        val pendingIntent = PendingIntent.getActivity(
            context, 2,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        )
        val notification = NotificationCompat.Builder(context, SECURITY_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(if (english) "Hydra Firewall stopped unexpectedly" else "Hydra Firewall se detuvo inesperadamente")
            .setContentText(
                if (english) "Not stopped from the app UI. It will try to restart automatically."
                else "No se detuvo desde la app. Va a intentar reiniciarse automáticamente."
            )
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(TAMPER_NOTIFICATION_ID, notification)
    }
    /**
     * Immediate notification for confirmed high/critical threats only.
     * Ad/tracker blocklist hits remain silent to avoid notification spam.
     */
    fun notifyThreatBlocked(
        context: Context,
        packageName: String?,
        indicator: String,
        family: String?,
        severity: Severity
    ) {
        if (severity != Severity.HIGH && severity != Severity.CRITICAL) return
        val key = "${packageName ?: "unknown"}|${indicator.lowercase(Locale.US)}|${family ?: ""}"
        val now = System.currentTimeMillis()
        val previous = threatNotifyTimes[key] ?: 0L
        if (now - previous < 10L * 60L * 1000L) return
        threatNotifyTimes[key] = now
        ensureSecurityChannel(context)

        val english = AppSettings(context).language.isEnglish() ||
            (AppSettings(context).language == AppLanguage.SYSTEM && Locale.getDefault().language.equals("en", true))
        val label = packageName?.let { pkg ->
            runCatching {
                context.packageManager.getApplicationInfo(pkg, 0).loadLabel(context.packageManager).toString()
            }.getOrNull()
        } ?: packageName ?: if (english) "Application" else "Aplicación"
        val pendingIntent = PendingIntent.getActivity(
            context,
            THREAT_NOTIFICATION_BASE_ID + (key.hashCode() and 0x3FF),
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        )
        val title = if (english) "Threat blocked" else "Amenaza bloqueada"
        val text = if (english)
            "$label • ${indicator.take(80)}${family?.let { " • $it" } ?: ""}"
        else
            "$label • ${indicator.take(80)}${family?.let { " • $it" } ?: ""}"
        val notification = NotificationCompat.Builder(context, SECURITY_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(
                if (english) "Hydra blocked a confirmed threat from $label.\n$indicator${family?.let { "\nFamily: $it" } ?: ""}"
                else "Hydra bloqueó una amenaza confirmada de $label.\n$indicator${family?.let { "\nFamilia: $it" } ?: ""}"
            ))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ERROR)
            .build()
        (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .notify(THREAT_NOTIFICATION_BASE_ID + (key.hashCode() and 0x3FF), notification)
    }

}
