package com.hydra.firewall.vpn

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Locale

/**
 * Persistencia local (solo en el teléfono, nunca exportada ni enviada) del consumo por app de los últimos 8 días.
 * La lógica de acumulación y límites vive en [DailyUsageLedger] (pura y testeada); esto solo la conecta con
 * SharedPreferences. Escribe a disco como máximo una vez por minuto.
 */
object AppDailyUsageStore {
    private const val PREFS = "hydra_app_daily_usage"
    private const val KEY = "ledger"
    private const val FLUSH_MS = 60_000L

    private var ledger = DailyUsageLedger()
    private var context: Context? = null
    private var initialized = false
    private var dirty = false
    private var lastFlush = 0L
    private var dayKey = ""
    private var dayValidUntil = 0L

    @Synchronized
    fun init(ctx: Context) {
        if (initialized) return
        context = ctx.applicationContext
        ledger = DailyUsageLedger.parse(runCatching { prefs()?.getString(KEY, null) }.getOrNull())
        lastFlush = System.currentTimeMillis()
        initialized = true
    }

    /** Llamado desde el camino de paquetes: debe ser barato. */
    @Synchronized
    fun add(uid: Int, packageName: String?, bytes: Int) {
        if (!initialized || bytes <= 0) return
        val key = packageName?.takeIf { it.isNotBlank() && it.length <= 200 } ?: "uid:$uid"
        ledger.add(today(), key, bytes.toLong())
        dirty = true
        val now = System.currentTimeMillis()
        if (now - lastFlush >= FLUSH_MS) flushLocked(now)
    }

    @Synchronized fun flush() { if (initialized) flushLocked(System.currentTimeMillis()) }

    @Synchronized fun todayTotals(): Map<String, Long> = ledger.day(today())

    /** Suma de los últimos [days] días, contando hoy. */
    @Synchronized
    fun lastDaysTotals(days: Int): Map<String, Long> {
        val cal = Calendar.getInstance()
        val keys = ArrayList<String>(days)
        repeat(days.coerceIn(1, 8)) {
            keys += dayKeyFor(cal.timeInMillis)
            cal.add(Calendar.DAY_OF_YEAR, -1)
        }
        return ledger.sum(keys)
    }

    @Synchronized
    fun clear() {
        ledger.clear()
        dirty = false
        runCatching { prefs()?.edit()?.remove(KEY)?.apply() }
    }

    private fun flushLocked(now: Long) {
        lastFlush = now
        if (!dirty) return
        dirty = false
        runCatching { prefs()?.edit()?.putString(KEY, ledger.serialize())?.apply() }
    }

    private fun prefs() = context?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun dayKeyFor(ms: Long): String = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(ms)

    /** La clave del día se recalcula solo al pasar la medianoche (no por paquete). */
    private fun today(): String {
        val now = System.currentTimeMillis()
        if (now >= dayValidUntil || dayKey.isEmpty()) {
            dayKey = dayKeyFor(now)
            val cal = Calendar.getInstance()
            cal.timeInMillis = now
            cal.set(Calendar.HOUR_OF_DAY, 0); cal.set(Calendar.MINUTE, 0); cal.set(Calendar.SECOND, 0); cal.set(Calendar.MILLISECOND, 0)
            cal.add(Calendar.DAY_OF_YEAR, 1)
            dayValidUntil = cal.timeInMillis
        }
        return dayKey
    }
}
