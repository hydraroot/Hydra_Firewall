package com.hydra.firewall.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.roundToInt

/** Separate, local privacy/tracking signal. It never labels an app as malware. */
object HydraPrivacyAiEngine {
    data class Features(
        val connections: Int,
        val uniqueDestinations: Int,
        val dnsQueries: Int,
        val dnsBlocks: Int,
        val recentConnections: Int,
        val newDestinations: Int,
        val sniBlocks: Int
    )

    data class Result(val score: Int, val level: RiskLevel, val explanation: String, val modelVersion: String)

    private data class Model(val version: String, val means: DoubleArray, val scales: DoubleArray, val weights: DoubleArray, val bias: Double)
    @Volatile private var model: Model? = null

    @Synchronized
    fun init(context: Context) {
        if (model != null) return
        model = runCatching {
            val text = context.applicationContext.assets.open("hydra_ai_privacy_v1.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
            parse(text)
        }.getOrNull()
    }

    fun isLoaded(): Boolean = model != null

    fun predict(f: Features): Result? {
        val m = model ?: return null
        val raw = doubleArrayOf(
            ln(1.0 + f.connections.coerceAtLeast(0)),
            ln(1.0 + f.uniqueDestinations.coerceAtLeast(0)),
            ln(1.0 + f.dnsQueries.coerceAtLeast(0)),
            f.dnsBlocks.coerceAtMost(30).coerceAtLeast(0).toDouble(),
            ln(1.0 + f.recentConnections.coerceAtLeast(0)),
            f.newDestinations.coerceAtMost(30).coerceAtLeast(0).toDouble(),
            f.sniBlocks.coerceAtMost(30).coerceAtLeast(0).toDouble(),
            f.dnsBlocks.coerceAtLeast(0).toDouble() / f.connections.coerceAtLeast(1),
            f.sniBlocks.coerceAtLeast(0).toDouble() / f.connections.coerceAtLeast(1)
        )
        var z = m.bias
        for (i in raw.indices) z += ((raw[i] - m.means[i]) / if (m.scales[i] == 0.0) 1.0 else m.scales[i]) * m.weights[i]
        val p = 1.0 / (1.0 + exp(-z))
        val score = (p * 100.0).roundToInt().coerceIn(0, 100)
        val level = when { score >= 80 -> RiskLevel.HIGH; score >= 55 -> RiskLevel.MEDIUM; score >= 25 -> RiskLevel.LOW; else -> RiskLevel.SAFE }
        val explanation = when {
            score >= 80 -> "Alta actividad publicitaria o de seguimiento detectada."
            score >= 55 -> "Se observan varias señales de publicidad/seguimiento."
            score >= 25 -> "Se observan algunas señales de seguimiento."
            else -> "No se observan señales fuertes de publicidad o seguimiento."
        }
        return Result(score, level, explanation, m.version)
    }

    private fun parse(text: String): Model {
        val root = JSONObject(text)
        fun arr(name: String) = root.getJSONArray(name).let { a -> DoubleArray(a.length()) { i -> a.getDouble(i) } }
        return Model(root.optString("model_version", "hydra-ai-privacy-v1"), arr("means"), arr("scales"), arr("weights"), root.getDouble("bias")).also {
            require(it.means.size == 9 && it.scales.size == 9 && it.weights.size == 9)
        }
    }
}
