package com.hydra.firewall.security

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.roundToInt

/**
 * Tiny, local behavior-anomaly model used as a secondary security signal.
 *
 * The model is intentionally NOT authoritative: it never blocks traffic by itself.
 * It only produces a risk signal from metadata Hydra already collects.
 */
object HydraAiEngine {
    data class BehaviorFeatures(
        val connections: Int,
        val uniqueDestinations: Int,
        val dnsQueries: Int,
        val dnsBlocks: Int,
        val tlsAlerts: Int,
        val unusualPorts: Int,
        val recentConnections: Int,
        val newDestinations: Int,
        val sniBlocks: Int
    )

    data class Result(
        val score: Int,
        val level: RiskLevel,
        val modelVersion: String,
        val explanation: String
    )

    private data class Model(
        val version: String,
        val means: DoubleArray,
        val scales: DoubleArray,
        val weights: DoubleArray,
        val bias: Double
    )

    @Volatile
    private var model: Model? = null

    @Synchronized
    fun init(context: Context) {
        if (model != null) return
        model = runCatching {
            val assetText = runCatching {
                context.applicationContext.assets.open("hydra_ai_model_v3.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
            }.getOrElse {
                runCatching {
                    context.applicationContext.assets.open("hydra_ai_model_v2.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
                }.getOrElse {
                    context.applicationContext.assets.open("hydra_ai_model_v1.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
                }
            }
            parseModel(assetText)
        }.getOrNull()
    }

    fun isLoaded(): Boolean = model != null

    fun predict(features: BehaviorFeatures): Result? {
        val m = model ?: return null
        val raw = doubleArrayOf(
            ln(1.0 + features.connections.coerceAtLeast(0)),
            ln(1.0 + features.uniqueDestinations.coerceAtLeast(0)),
            ln(1.0 + features.dnsQueries.coerceAtLeast(0)),
            features.dnsBlocks.coerceAtLeast(0).coerceAtMost(20).toDouble(),
            features.tlsAlerts.coerceAtLeast(0).coerceAtMost(10).toDouble(),
            features.unusualPorts.coerceAtLeast(0).coerceAtMost(20).toDouble(),
            ln(1.0 + features.recentConnections.coerceAtLeast(0)),
            features.newDestinations.coerceAtLeast(0).coerceAtMost(20).toDouble(),
            features.sniBlocks.coerceAtLeast(0).coerceAtMost(20).toDouble(),
            ratio(features.dnsBlocks, features.connections),
            ratio(features.unusualPorts, features.connections),
            ratio(features.newDestinations, features.uniqueDestinations),
            ratio(features.uniqueDestinations, features.connections),
            ratio(features.tlsAlerts, features.connections)
        )

        var z = m.bias
        for (i in raw.indices) {
            val scale = if (m.scales[i] == 0.0) 1.0 else m.scales[i]
            z += ((raw[i] - m.means[i]) / scale) * m.weights[i]
        }
        val probability = 1.0 / (1.0 + exp(-z))
        val score = (probability * 100.0).roundToInt().coerceIn(0, 100)
        val level = when {
            score >= 85 -> RiskLevel.CRITICAL
            score >= 65 -> RiskLevel.HIGH
            score >= 40 -> RiskLevel.MEDIUM
            score >= 20 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }
        val explanation = when {
            score >= 65 -> "Comportamiento poco habitual; revisar la actividad de red."
            score >= 40 -> "Se observan señales que merecen atención."
            score >= 20 -> "Hay pequeñas desviaciones respecto de un comportamiento normal."
            else -> "No se observan señales fuertes de comportamiento anómalo."
        }
        return Result(score, level, m.version, explanation)
    }

    internal fun loadModelForTest(json: String) {
        model = parseModel(json)
    }

    private fun ratio(value: Int, total: Int): Double =
        value.coerceAtLeast(0).toDouble() / total.coerceAtLeast(1).toDouble()

    private fun parseModel(text: String): Model {
        val root = JSONObject(text)
        return Model(
            version = root.optString("model_version", "hydra-ai-lite"),
            means = root.getDoubleArray("means"),
            scales = root.getDoubleArray("scales"),
            weights = root.getDoubleArray("weights"),
            bias = root.getDouble("bias")
        ).also {
            require(it.means.size == it.scales.size)
            require(it.means.size == it.weights.size)
            require(it.means.size == 14)
        }
    }

    private fun JSONObject.getDoubleArray(name: String): DoubleArray {
        val array: JSONArray = getJSONArray(name)
        return DoubleArray(array.length()) { index -> array.getDouble(index) }
    }
}
