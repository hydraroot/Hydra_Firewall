package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Avisos del tipo "la app X se conecta a Y, ¿la bloqueamos?". Un aviso nace PENDING; el usuario lo bloquea (BLOCKED,
 * se agrega la IP a [IpBlockStore]), lo deja pasar (IGNORED) o lo desbloquea después desde Reglas (UNBLOCKED).
 */
object AlertStore {
    enum class Status { PENDING, BLOCKED, IGNORED, UNBLOCKED }
    enum class Reason { THREAT, NEW_DESTINATION }

    data class Alert(
        val id: Long,
        val uid: Int,
        val packageName: String?,
        val appLabel: String,
        val host: String,       // dominio si se conoce, si no la IP
        val ip: String,
        val reason: Reason,
        val createdAt: Long,
        val status: Status,
        val changedAt: Long
    )

    private const val PREFS = "hydra_alerts"
    private const val KEY = "alerts"
    private const val MAX = 60
    /** Ventana en la que el botón se convierte en "Deshacer". */
    const val UNDO_WINDOW_MS = 5_000L

    private val lock = Any()

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private fun load(context: Context): MutableList<Alert> = synchronized(lock) {
        val raw = prefs(context).getString(KEY, null) ?: return mutableListOf()
        runCatching {
            val arr = JSONArray(raw)
            MutableList(arr.length()) { i ->
                val o = arr.getJSONObject(i)
                Alert(
                    o.getLong("id"), o.getInt("uid"), o.optString("pkg").ifBlank { null }, o.optString("app"),
                    o.optString("host"), o.optString("ip"),
                    runCatching { Reason.valueOf(o.optString("reason")) }.getOrDefault(Reason.NEW_DESTINATION),
                    o.getLong("at"),
                    runCatching { Status.valueOf(o.optString("status")) }.getOrDefault(Status.PENDING),
                    o.optLong("chg", o.getLong("at"))
                )
            }
        }.getOrDefault(mutableListOf())
    }

    private fun save(context: Context, list: List<Alert>) = synchronized(lock) {
        val arr = JSONArray()
        list.takeLast(MAX).forEach { a ->
            arr.put(
                JSONObject().put("id", a.id).put("uid", a.uid).put("pkg", a.packageName ?: "").put("app", a.appLabel)
                    .put("host", a.host).put("ip", a.ip).put("reason", a.reason.name).put("at", a.createdAt)
                    .put("status", a.status.name).put("chg", a.changedAt)
            )
        }
        prefs(context).edit().putString(KEY, arr.toString()).apply()
    }

    fun get(context: Context, id: Long): Alert? = load(context).firstOrNull { it.id == id }

    /** Crea un aviso PENDING salvo que ya haya uno (pendiente, bloqueado o ignorado) para la misma app y destino. */
    fun create(context: Context, uid: Int, pkg: String?, appLabel: String, host: String, ip: String, reason: Reason): Alert? =
        synchronized(lock) {
            val list = load(context)
            if (list.any { it.uid == uid && it.ip == ip && it.status != Status.UNBLOCKED }) return null
            val now = System.currentTimeMillis()
            val a = Alert(now, uid, pkg, appLabel, host, ip, reason, now, Status.PENDING, now)
            list.removeAll { it.uid == uid && it.ip == ip }
            list.add(a)
            save(context, list)
            a
        }

    private fun update(context: Context, id: Long, status: Status): Alert? = synchronized(lock) {
        val list = load(context)
        val idx = list.indexOfFirst { it.id == id }
        if (idx < 0) return null
        val updated = list[idx].copy(status = status, changedAt = System.currentTimeMillis())
        list[idx] = updated
        save(context, list)
        updated
    }

    /** Bloquea el destino (IP) para todo el dispositivo. */
    fun block(context: Context, id: Long): Alert? {
        val a = update(context, id, Status.BLOCKED) ?: return null
        if (a.ip.isNotBlank()) IpBlockStore(context).add(a.ip)
        return a
    }

    /** Deshace un bloqueo: la IP sale de la lista. [back] = estado al que vuelve el aviso. */
    fun unblock(context: Context, id: Long, back: Status = Status.UNBLOCKED): Alert? {
        val a = update(context, id, back) ?: return null
        if (a.ip.isNotBlank()) IpBlockStore(context).remove(a.ip)
        return a
    }

    fun ignore(context: Context, id: Long): Alert? = update(context, id, Status.IGNORED)

    /** Avisos a mostrar en Inicio: pendientes + los bloqueados hace menos de la ventana de deshacer (+1 s de margen). */
    fun visibleOnHome(context: Context): List<Alert> {
        val now = System.currentTimeMillis()
        return load(context).filter {
            it.status == Status.PENDING || (it.status == Status.BLOCKED && now - it.changedAt <= UNDO_WINDOW_MS + 1_000L)
        }.sortedByDescending { it.createdAt }
    }

    fun pendingCount(context: Context): Int = load(context).count { it.status == Status.PENDING }

    fun blocked(context: Context): List<Alert> =
        load(context).filter { it.status == Status.BLOCKED }.sortedByDescending { it.changedAt }

    /** El usuario dijo "Dejar" para este destino: no se vuelve a avisar. */
    fun isIgnored(context: Context, uid: Int, ip: String): Boolean =
        load(context).any { it.uid == uid && it.ip == ip && it.status == Status.IGNORED }
}
