package com.hydra.firewall.security

import android.content.Context
import org.json.JSONObject
import java.util.Locale
import kotlin.math.ln

/**
 * Tiny on-device learning layer. It learns each app's normal traffic profile
 * from real observations on this device. It is not a blocker and does not
 * require cloud data.
 */
object AppBehaviorBaselineStore {
    private const val PREFS = "hydra_behavior_baselines"
    private const val KEY = "profiles"
    private const val MAX_APPS = 200
    private const val MAX_SAMPLES = 60
    /**
     * Una "muestra" es una observación espaciada, no un refresco de pantalla. Sin este límite, abrir la pestaña
     * 3 veces completaba el aprendizaje y unos pocos refrescos más absorbían una anomalía como si fuera lo normal.
     */
    internal const val MIN_OBSERVE_INTERVAL_MS = 15L * 60L * 1000L

    data class Features(
        val connections: Int,
        val uniqueDestinations: Int,
        val dnsQueries: Int,
        val recentConnections: Int,
        val newDestinations: Int,
        val unusualPorts: Int,
        val sniBlocks: Int
    )

    data class Comparison(val score: Int, val explanation: String, val trainedSamples: Int)

    private data class Profile(var samples: Int, var c: Double, var u: Double, var d: Double, var r: Double, var n: Double, var p: Double, var s: Double, var t: Long = 0L)

    private var cache: MutableMap<String, Profile>? = null

    @Synchronized
    fun compare(context: Context, packageName: String, f: Features): Comparison {
        val profile = load(context)[packageName] ?: return Comparison(0, "Sin baseline suficiente todavía.", 0)
        if (profile.samples < 3) return Comparison(0, "La app todavía está aprendiendo su comportamiento normal.", profile.samples)
        val values = doubleArrayOf(
            f.connections.toDouble(), f.uniqueDestinations.toDouble(), f.dnsQueries.toDouble(),
            f.recentConnections.toDouble(), f.newDestinations.toDouble(), f.unusualPorts.toDouble(), f.sniBlocks.toDouble()
        )
        val means = doubleArrayOf(profile.c, profile.u, profile.d, profile.r, profile.n, profile.p, profile.s)
        val names = arrayOf("conexiones", "destinos", "consultas DNS", "actividad reciente", "destinos nuevos", "puertos inusuales", "bloqueos SNI")
        var score = 0.0
        val reasons = mutableListOf<String>()
        for (i in values.indices) {
            val ratio = (values[i] + 1.0) / (means[i] + 1.0)
            val contribution = when {
                ratio >= 8.0 -> 22.0
                ratio >= 4.0 -> 15.0
                ratio >= 2.5 -> 8.0
                else -> 0.0
            }
            if (contribution > 0) {
                score += contribution
                reasons += "${names[i]} x${String.format(Locale.US, "%.1f", ratio)}"
            }
        }
        val finalScore = score.coerceIn(0.0, 100.0).toInt()
        val explanation = if (reasons.isEmpty()) {
            "Comportamiento cercano al baseline aprendido."
        } else {
            "Cambio respecto del comportamiento habitual: ${reasons.take(3).joinToString(", ")}."
        }
        return Comparison(finalScore, explanation, profile.samples)
    }

    @Synchronized
    fun observe(context: Context, packageName: String, f: Features, now: Long = System.currentTimeMillis()) {
        val data = load(context)
        val p = data[packageName]
        if (p != null && p.t > 0L) {
            val age = now - p.t
            if (age >= 0L && age < MIN_OBSERVE_INTERVAL_MS) return
        }
        if (p == null) {
            data[packageName] = Profile(1, f.connections.toDouble(), f.uniqueDestinations.toDouble(), f.dnsQueries.toDouble(), f.recentConnections.toDouble(), f.newDestinations.toDouble(), f.unusualPorts.toDouble(), f.sniBlocks.toDouble(), now)
        } else {
            val alpha = if (p.samples < 10) 0.35 else 0.20
            p.samples = (p.samples + 1).coerceAtMost(MAX_SAMPLES)
            p.t = now
            p.c = ema(p.c, f.connections.toDouble(), alpha)
            p.u = ema(p.u, f.uniqueDestinations.toDouble(), alpha)
            p.d = ema(p.d, f.dnsQueries.toDouble(), alpha)
            p.r = ema(p.r, f.recentConnections.toDouble(), alpha)
            p.n = ema(p.n, f.newDestinations.toDouble(), alpha)
            p.p = ema(p.p, f.unusualPorts.toDouble(), alpha)
            p.s = ema(p.s, f.sniBlocks.toDouble(), alpha)
        }
        if (data.size > MAX_APPS) {
            // Se descartan las apps observadas hace más tiempo, nunca la que se acaba de observar
            // (antes se descartaba la de menos muestras: una app nueva no llegaba a aprender con el cupo lleno).
            val remove = data.entries.filter { it.key != packageName }.sortedBy { it.value.t }.take(data.size - MAX_APPS).map { it.key }
            remove.forEach(data::remove)
        }
        save(context, data)
    }

    @Synchronized
    fun trainedApps(context: Context): Int = load(context).size

    private fun ema(old: Double, current: Double, alpha: Double): Double = old + (current - old) * alpha

    private fun load(context: Context): MutableMap<String, Profile> {
        cache?.let { return it }
        val raw = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null)
        val loaded: MutableMap<String, Profile> = if (raw == null) mutableMapOf() else runCatching {
            val root = JSONObject(raw)
            val m = mutableMapOf<String, Profile>()
            root.keys().forEach { pkg ->
                val o = root.optJSONObject(pkg) ?: return@forEach
                m[pkg] = Profile(
                    o.optInt("samples", 0), o.optDouble("c", 0.0), o.optDouble("u", 0.0), o.optDouble("d", 0.0),
                    o.optDouble("r", 0.0), o.optDouble("n", 0.0), o.optDouble("p", 0.0), o.optDouble("s", 0.0),
                    o.optLong("t", 0L)
                )
            }
            m
        }.getOrDefault(mutableMapOf())
        cache = loaded
        return loaded
    }

    private fun save(context: Context, data: Map<String, Profile>) {
        val root = JSONObject()
        data.forEach { (pkg, p) ->
            root.put(pkg, JSONObject().apply {
                put("samples", p.samples); put("c", p.c); put("u", p.u); put("d", p.d)
                put("r", p.r); put("n", p.n); put("p", p.p); put("s", p.s); put("t", p.t)
            })
        }
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, root.toString()).apply()
    }
}
