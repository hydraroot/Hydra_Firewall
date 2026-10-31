package com.hydra.firewall.security

import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.zip.ZipFile
import kotlin.math.min

/**
 * Small Android-safe YARA subset used by Hydra threat packs.
 *
 * Supported:
 *   rule NAME { meta: severity/family/description; strings: $a = "literal" ascii nocase;
 *   condition: any of them | all of them | N of them }
 *
 * This is deliberately a subset rather than the full YARA language. Full YARA
 * source can be compiled into compatible Hydra rules offline before signing a
 * production pack.
 */
object HydraYaraLite {
    data class Rule(
        val name: String,
        val family: String?,
        val severityScore: Int,
        val description: String,
        val source: String,
        val patterns: List<PatternSpec>,
        val condition: Condition
    )

    /**
     * [alt] es la variante UTF-16LE del mismo literal: el AndroidManifest binario guarda las cadenas
     * (permisos) en UTF-16 en muchos APK, así que un literal "ascii" nunca coincidía ahí.
     */
    data class PatternSpec(val id: String, val bytes: ByteArray, val nocase: Boolean, val alt: ByteArray? = null)
    sealed class Condition {
        data object AnyOfThem : Condition()
        data object AllOfThem : Condition()
        data class AtLeast(val count: Int) : Condition()
    }

    fun parse(source: String): List<Rule> {
        val result = mutableListOf<Rule>()
        val ruleRegex = Regex("(?is)\\brule\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\{(.*?)\\n?\\}")
        for (m in ruleRegex.findAll(source)) {
            val name = m.groupValues[1]
            val body = m.groupValues[2]
            val meta = parseMeta(body)
            val stringsText = Regex("(?is)\\bstrings\\s*:\\s*(.*?)(?=\\bcondition\\s*:)").find(body)?.groupValues?.get(1).orEmpty()
            val conditionText = Regex("(?is)\\bcondition\\s*:\\s*(.*)$").find(body)?.groupValues?.get(1).orEmpty().trim()
            val patterns = parsePatterns(stringsText)
            if (patterns.isEmpty()) continue
            val condition = parseCondition(conditionText, patterns.size)
            result += Rule(
                name = name,
                family = meta["family"],
                severityScore = meta["severity"]?.toIntOrNull()?.coerceIn(0, 100) ?: 50,
                description = meta["description"].orEmpty().ifBlank { "Hydra YARA signature match" },
                source = source,
                patterns = patterns,
                condition = condition
            )
        }
        return result
    }

    fun scanApk(file: File, rules: List<Rule>, maxBytesTotal: Long = 16L * 1024L * 1024L, maxMillis: Long = 10_000L): List<ThreatSignatureMatch> {
        val deadline = System.currentTimeMillis() + maxMillis
        if (rules.isEmpty() || !file.isFile || !file.canRead()) return emptyList()
        // Coincidencias acumuladas en TODO el APK: los permisos viven en AndroidManifest.xml y las APIs en
        // classes.dex, así que una regla combinada debe poder sumar patrones de archivos distintos.
        val hits = rules.associateWith { mutableSetOf<Int>() }
        val firstEntry = HashMap<String, String>()
        var remaining = maxBytesTotal
        runCatching {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements() && remaining > 0L && System.currentTimeMillis() < deadline) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue
                    val lower = entry.name.lowercase(Locale.US)
                    val interesting = lower == "androidmanifest.xml" ||
                        lower.endsWith(".dex") || lower.startsWith("assets/") || lower.startsWith("res/raw/") || lower.endsWith(".so")
                    if (!interesting) continue
                    val declared = entry.size.takeIf { it >= 0L } ?: 0L
                    val budget = min(remaining, min(2L * 1024L * 1024L, if (declared > 0) declared else 2L * 1024L * 1024L))
                    val bytes = zip.getInputStream(entry).use { input ->
                        val out = ByteArray(budget.toInt().coerceAtLeast(1))
                        var total = 0
                        while (total < out.size) {
                            val n = input.read(out, total, out.size - total)
                            if (n <= 0) break
                            total += n
                        }
                        out.copyOf(total)
                    }
                    remaining -= bytes.size.toLong()
                    if (bytes.isEmpty()) continue
                    for (rule in rules) {
                        if (System.currentTimeMillis() >= deadline) break
                        val seen = hits.getValue(rule)
                        if (seen.size == rule.patterns.size) continue
                        for ((idx, p) in rule.patterns.withIndex()) {
                            if (idx in seen) continue
                            if (contains(bytes, p.bytes, p.nocase) || (p.alt != null && contains(bytes, p.alt, p.nocase))) {
                                seen += idx
                                firstEntry.putIfAbsent(rule.name, entry.name)
                            }
                        }
                    }
                }
            }
        }
        val matches = linkedMapOf<String, ThreatSignatureMatch>()
        for (rule in rules) {
            if (!conditionHolds(rule, hits.getValue(rule).size)) continue
            matches[rule.name] = ThreatSignatureMatch(
                kind = ThreatSignatureMatch.Kind.YARA,
                name = rule.name,
                family = rule.family,
                source = "Hydra YARA pack",
                severity = scoreSeverity(rule.severityScore),
                confidence = rule.severityScore.coerceIn(0, 100),
                detail = "${rule.description} • entrada ${firstEntry[rule.name].orEmpty()}"
            )
        }
        return matches.values.toList()
    }

    private fun parseMeta(body: String): Map<String, String> {
        val meta = mutableMapOf<String, String>()
        val section = Regex("(?is)\\bmeta\\s*:\\s*(.*?)(?=\\bstrings\\s*:)").find(body)?.groupValues?.get(1).orEmpty()
        val lineRegex = Regex("(?m)^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(?:\\\"([^\\\"]*)\\\"|([^\\s]+))\\s*$")
        for (m in lineRegex.findAll(section)) meta[m.groupValues[1]] = m.groupValues[2].ifBlank { m.groupValues[3] }
        return meta
    }

    private fun parsePatterns(section: String): List<PatternSpec> {
        val out = mutableListOf<PatternSpec>()
        val lineRegex = Regex("(?m)^\\s*(\\$[A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*(\\\"([^\\\"]*)\\\"|\\{([^}]*)\\})(?:\\s+(?:ascii|nocase|wide|fullword))*\\s*$", RegexOption.MULTILINE)
        for (m in lineRegex.findAll(section)) {
            val id = m.groupValues[1]
            val quoted = m.groupValues[3]
            val hex = m.groupValues[4]
            val full = m.value.lowercase(Locale.US)
            val nocase = " nocase" in full
            val wide = " wide" in full
            val ascii = " ascii" in full
            val base = if (quoted.isNotEmpty()) quoted.toByteArray(StandardCharsets.UTF_8) else parseHex(hex) ?: continue
            val widened = if (quoted.isNotEmpty()) {
                ByteArray(base.size * 2).also { w -> for (i in base.indices) { w[i * 2] = base[i]; w[i * 2 + 1] = 0 } }
            } else null
            // "wide" solo => solo UTF-16. Resto (ascii, sin modificador, "wide ascii") => ASCII + variante UTF-16.
            val bytes = if (wide && !ascii && widened != null) widened else base
            val alt = if (widened != null && !(wide && !ascii)) widened else null
            out += PatternSpec(id, bytes, nocase = nocase, alt = alt)
        }
        return out
    }

    private fun parseHex(raw: String): ByteArray? {
        val tokens = raw.trim().split(Regex("\\s+")).filter { it.isNotBlank() }
        val out = ByteArray(tokens.size)
        for ((i, token) in tokens.withIndex()) {
            if (token.length != 2 || token.any { it !in "0123456789abcdefABCDEF" }) return null
            out[i] = token.toInt(16).toByte()
        }
        return out
    }

    private fun parseCondition(condition: String, count: Int): Condition {
        val c = condition.replace(Regex("//.*"), "").trim().lowercase(Locale.US)
        if (Regex("\\ball\\s+of\\s+them\\b").containsMatchIn(c)) return Condition.AllOfThem
        if (Regex("\\bany\\s+of\\s+them\\b").containsMatchIn(c)) return Condition.AnyOfThem
        val n = Regex("(\\d+)\\s+of\\s+them").find(c)?.groupValues?.get(1)?.toIntOrNull()
        return if (n != null) Condition.AtLeast(n.coerceIn(1, count)) else Condition.AnyOfThem
    }

    private fun conditionHolds(rule: Rule, matched: Int): Boolean = when (val c = rule.condition) {
        Condition.AnyOfThem -> matched >= 1
        Condition.AllOfThem -> matched == rule.patterns.size
        is Condition.AtLeast -> matched >= c.count
    }

    private fun contains(haystack: ByteArray, needle: ByteArray, nocase: Boolean): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                var a = haystack[i + j].toInt() and 0xFF
                var b = needle[j].toInt() and 0xFF
                if (nocase) {
                    if (a in 65..90) a += 32
                    if (b in 65..90) b += 32
                }
                if (a != b) continue@outer
            }
            return true
        }
        return false
    }

    private fun scoreSeverity(score: Int): Severity = when {
        score >= 90 -> Severity.CRITICAL
        score >= 70 -> Severity.HIGH
        score >= 40 -> Severity.MEDIUM
        else -> Severity.LOW
    }
}
