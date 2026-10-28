package com.hydra.firewall.vpn

import java.util.TreeMap

/**
 * Punto 5 — Consumo por app. Lógica PURA: ranking con banderas ("habla de más") y un libro diario persistible
 * para ver hoy / últimos 7 días. No mide nada por sí sola: recibe los bytes que ya cuenta TrafficStatsStore.
 */
object AppUsageInsights {

    enum class Flag { HEAVY_DATA, UPLOAD_HEAVY, CHATTY, MOSTLY_BLOCKED }

    data class Input(
        val key: String,
        val packageName: String?,
        val uid: Int,
        val txBytes: Long,
        val rxBytes: Long,
        val connections: Long,
        val blocked: Long
    )

    data class Row(
        val key: String,
        val packageName: String?,
        val uid: Int,
        val totalBytes: Long,
        val txBytes: Long,
        val rxBytes: Long,
        val sharePercent: Int,
        val connections: Long,
        val blocked: Long,
        val flags: Set<Flag>
    )

    // Umbrales (documentados para poder ajustarlos y testearlos)
    const val HEAVY_SHARE_PERCENT = 40
    const val HEAVY_MIN_BYTES = 5L * 1024 * 1024
    const val UPLOAD_MIN_BYTES = 5L * 1024 * 1024
    const val UPLOAD_RATIO = 2.0
    const val CHATTY_CONNECTIONS = 200L
    const val MOSTLY_BLOCKED_MIN = 20L

    fun rank(inputs: List<Input>, topN: Int = 10): List<Row> {
        val totalAll = inputs.sumOf { (it.txBytes + it.rxBytes).coerceAtLeast(0L) }
        return inputs
            .filter { it.txBytes + it.rxBytes > 0 || it.connections > 0 || it.blocked > 0 }
            .map { i ->
                val tx = i.txBytes.coerceAtLeast(0L)
                val rx = i.rxBytes.coerceAtLeast(0L)
                val total = tx + rx
                val share = if (totalAll > 0) ((total * 100.0) / totalAll).toInt().coerceIn(0, 100) else 0
                val flags = mutableSetOf<Flag>()
                if (share >= HEAVY_SHARE_PERCENT && total >= HEAVY_MIN_BYTES) flags += Flag.HEAVY_DATA
                if (tx >= UPLOAD_MIN_BYTES && tx > rx * UPLOAD_RATIO) flags += Flag.UPLOAD_HEAVY
                if (i.connections >= CHATTY_CONNECTIONS) flags += Flag.CHATTY
                if (i.blocked >= MOSTLY_BLOCKED_MIN && i.blocked > i.connections * 2) flags += Flag.MOSTLY_BLOCKED
                Row(i.key, i.packageName, i.uid, total, tx, rx, share, i.connections.coerceAtLeast(0L), i.blocked.coerceAtLeast(0L), flags)
            }
            .sortedWith(compareByDescending<Row> { it.totalBytes }.thenByDescending { it.connections + it.blocked }.thenBy { it.key })
            .take(topN.coerceAtLeast(1))
    }

    fun flagText(flag: Flag, english: Boolean): String = when (flag) {
        Flag.HEAVY_DATA -> if (english) "uses most of the data" else "consume la mayor parte de los datos"
        Flag.UPLOAD_HEAVY -> if (english) "uploads more than it downloads" else "sube más de lo que baja"
        Flag.CHATTY -> if (english) "very many connections" else "muchísimas conexiones"
        Flag.MOSTLY_BLOCKED -> if (english) "keeps trying and gets blocked" else "insiste y se la bloquea"
    }

    fun formatBytes(bytes: Long): String {
        val b = bytes.coerceAtLeast(0L).toDouble()
        return when {
            b < 1024 -> "${b.toLong()} B"
            b < 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f KB", b / 1024)
            b < 1024.0 * 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB", b / (1024 * 1024))
            else -> String.format(java.util.Locale.US, "%.2f GB", b / (1024.0 * 1024 * 1024))
        }
    }
}

/**
 * Libro de bytes por día y por app (clave = paquete o "uid:N"). Sin Android: serializable a texto,
 * con tope de días y de apps por día para que el almacenamiento nunca crezca sin límite.
 */
class DailyUsageLedger(private val keepDays: Int = 8, private val maxKeysPerDay: Int = 400) {
    private val days = TreeMap<String, MutableMap<String, Long>>()

    fun add(dayKey: String, key: String, bytes: Long) {
        if (bytes <= 0L || !validDay(dayKey) || !validKey(key)) return
        val day = days.getOrPut(dayKey) { HashMap() }
        if (key !in day && day.size >= maxKeysPerDay) return
        day[key] = (day[key] ?: 0L) + bytes
        while (days.size > keepDays) days.remove(days.firstKey())
    }

    fun day(dayKey: String): Map<String, Long> = days[dayKey]?.toMap().orEmpty()

    fun sum(dayKeys: Collection<String>): Map<String, Long> {
        val out = HashMap<String, Long>()
        for (d in dayKeys) days[d]?.forEach { (k, v) -> out[k] = (out[k] ?: 0L) + v }
        return out
    }

    fun clear() = days.clear()
    fun dayKeys(): List<String> = days.keys.toList()

    fun serialize(): String = buildString {
        for ((d, m) in days) for ((k, v) in m) append(d).append('\t').append(k).append('\t').append(v).append('\n')
    }

    companion object {
        private val DAY = Regex("^\\d{4}-\\d{2}-\\d{2}$")
        private val KEY = Regex("^[A-Za-z0-9_.:\\-]{1,200}$")
        private fun validDay(s: String) = DAY.matches(s)
        private fun validKey(s: String) = KEY.matches(s)

        fun parse(text: String?, keepDays: Int = 8, maxKeysPerDay: Int = 400): DailyUsageLedger {
            val l = DailyUsageLedger(keepDays, maxKeysPerDay)
            if (text.isNullOrEmpty() || text.length > 4_000_000) return l
            for (line in text.lineSequence()) {
                val p = line.split('\t')
                if (p.size != 3) continue
                val v = p[2].toLongOrNull() ?: continue
                l.add(p[0], p[1], v)
            }
            return l
        }
    }
}
