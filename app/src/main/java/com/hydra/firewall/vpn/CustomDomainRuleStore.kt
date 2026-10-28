package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference

/**
 * Explicit domain policy owned by the user.
 *
 * Most-specific match wins. A confirmed ThreatSignature always has priority
 * over an ALLOW rule; the allowlist only overrides advertising/tracker
 * blocklists. This prevents an accidental whitelist from disabling a known
 * malicious-domain signature.
 */
object CustomDomainRuleStore {
    enum class Action { BLOCK, ALLOW }
    data class Rule(val domain: String, val action: Action)

    private const val PREFS = "hydra_custom_domain_rules"
    private const val KEY_RULES = "rules"
    private val cachedRules = AtomicReference<Map<String, Action>>(emptyMap())
    @Volatile private var initialized = false

    fun normalize(input: String): String? {
        var value = input.trim().lowercase(Locale.US)
        if (value.isBlank()) return null
        value = value.removePrefix("https://").removePrefix("http://")
        value = value.substringBefore('/').substringBefore('?').substringBefore('#')
        value = value.removePrefix("*.").removePrefix(".").trimEnd('.')
        if (value.isBlank() || value.contains(':') || value.contains(' ')) return null
        val labels = value.split('.')
        if (labels.size < 2 || labels.any { it.isBlank() || it.length > 63 }) return null
        if (value.length > 253) return null
        if (!value.matches(Regex("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?"))) return null
        return value
    }

    @Synchronized
    fun snapshot(context: Context): List<Rule> {
        ensureLoaded(context)
        return cachedRules.get().map { Rule(it.key, it.value) }.sortedBy { it.domain }
    }

    @Synchronized
    fun set(context: Context, domain: String, action: Action): Boolean {
        val normalized = normalize(domain) ?: return false
        ensureLoaded(context)
        val rules = snapshot(context).toMutableList()
        rules.removeAll { it.domain == normalized }
        rules.add(Rule(normalized, action))
        persist(context, rules)
        return true
    }

    @Synchronized
    fun remove(context: Context, domain: String) {
        val normalized = normalize(domain) ?: return
        ensureLoaded(context)
        persist(context, snapshot(context).filterNot { it.domain == normalized })
    }

    /** Returns the most-specific user rule, or null when no explicit rule exists. */
    fun decision(context: Context, domain: String): Action? {
        val normalized = normalize(domain) ?: return null
        ensureLoaded(context)
        val rules = cachedRules.get()
        var current = normalized
        while (true) {
            rules[current]?.let { return it }
            val dot = current.indexOf('.')
            if (dot < 0) return null
            current = current.substring(dot + 1)
            if (current.isEmpty() || !current.contains('.')) return null
        }
    }

    fun clear(context: Context) {
        prefs(context).edit().remove(KEY_RULES).apply()
        cachedRules.set(emptyMap())
        initialized = true
    }

    private fun ensureLoaded(context: Context) {
        if (initialized) return
        val raw = prefs(context).getString(KEY_RULES, null)
        val loaded = runCatching {
            val array = JSONArray(raw ?: "[]")
            buildMap {
                for (i in 0 until array.length()) {
                    val o = array.optJSONObject(i) ?: continue
                    val domain = normalize(o.optString("domain")) ?: continue
                    val action = runCatching { Action.valueOf(o.optString("action")) }.getOrNull() ?: continue
                    put(domain, action)
                }
            }
        }.getOrDefault(emptyMap())
        cachedRules.set(loaded)
        initialized = true
    }

    private fun persist(context: Context, rules: List<Rule>) {
        val array = JSONArray()
        rules.distinctBy { "${it.domain}:${it.action}" }.sortedBy { it.domain }.forEach { rule ->
            array.put(JSONObject().apply {
                put("domain", rule.domain)
                put("action", rule.action.name)
            })
        }
        prefs(context).edit().putString(KEY_RULES, array.toString()).apply()
        cachedRules.set(rules.associate { it.domain to it.action })
        initialized = true
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
