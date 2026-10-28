package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Persistent advanced protocol + destination-port rules.
 * Uses one JSON document so rules survive process restarts and remain easy to enumerate/delete.
 * Legacy per-key rules are migrated on first read.
 */
class AdvancedRuleStore(context: Context) {
    companion object {
        const val GLOBAL_UID = -1
        private const val PREFS_NAME = "firewall_advanced_rules"
        private const val KEY_RULES_JSON = "rules_json"
        private const val LEGACY_MARKER = "_legacy_migrated"
    }

    data class Rule(val uid: Int, val protocol: String, val startPort: Int, val endPort: Int, val allowed: Boolean)
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    fun getAll(): List<Rule> {
        val json = prefs.getString(KEY_RULES_JSON, null)
        if (json != null) return parseJson(json)

        val legacy = prefs.all.keys.mapNotNull { key ->
            val parts = key.split(':')
            if (parts.size != 5 || parts[0] != "r") return@mapNotNull null
            runCatching {
                Rule(parts[1].toInt(), parts[2].uppercase(), parts[3].toInt(), parts[4].toInt(), prefs.getBoolean(key, true))
            }.getOrNull()
        }.toMutableList()
        if (legacy.isNotEmpty()) {
            saveAll(legacy)
            prefs.edit().remove(LEGACY_MARKER).apply()
        }
        return legacy.sortedWith(compareBy<Rule> { it.uid }.thenBy { it.protocol }.thenBy { it.startPort }.thenBy { it.endPort })
    }

    @Synchronized
    fun set(uid: Int, protocol: String, startPort: Int, endPort: Int, allowed: Boolean) {
        if (uid < GLOBAL_UID) return
        val p = protocol.uppercase()
        val s = startPort.coerceIn(1, 65535)
        val e = endPort.coerceIn(s, 65535)
        val updated = getAll().filterNot { it.uid == uid && it.protocol == p && it.startPort == s && it.endPort == e }
            .toMutableList()
        updated += Rule(uid, p, s, e, allowed)
        saveAll(updated)
    }

    @Synchronized
    fun remove(rule: Rule) {
        saveAll(getAll().filterNot { it.uid == rule.uid && it.protocol == rule.protocol && it.startPort == rule.startPort && it.endPort == rule.endPort })
    }

    fun findMatches(uid: Int, protocol: String, port: Int): List<Rule> =
        getAll().filter {
            (it.uid == GLOBAL_UID || it.uid == uid) &&
                it.protocol == protocol.uppercase() &&
                port in it.startPort..it.endPort
        }

    @Synchronized
    fun clearAll() {
        prefs.edit().remove(KEY_RULES_JSON).remove(LEGACY_MARKER).commit()
    }

    fun clearForUid(uid: Int) {
        saveAll(getAll().filterNot { it.uid == uid })
    }

    fun evaluate(uid: Int, protocol: String, port: Int): Boolean? {
        val p = protocol.uppercase()
        // App-specific rules have priority over global rules. Within the same scope,
        // the narrowest matching port range wins.
        val all = getAll()
        val appMatch = all
            .filter { it.uid == uid && it.protocol == p && port in it.startPort..it.endPort }
            .minByOrNull { it.endPort - it.startPort }
        if (appMatch != null) return appMatch.allowed
        return all
            .filter { it.uid == GLOBAL_UID && it.protocol == p && port in it.startPort..it.endPort }
            .minByOrNull { it.endPort - it.startPort }
            ?.allowed
    }

    @Synchronized
    private fun saveAll(rules: List<Rule>) {
        val arr = JSONArray()
        rules.distinctBy { "${it.uid}:${it.protocol}:${it.startPort}:${it.endPort}" }
            .sortedWith(compareBy<Rule> { it.uid }.thenBy { it.protocol }.thenBy { it.startPort }.thenBy { it.endPort })
            .forEach { r ->
                arr.put(JSONObject().apply {
                    put("uid", r.uid)
                    put("protocol", r.protocol)
                    put("start", r.startPort)
                    put("end", r.endPort)
                    put("allowed", r.allowed)
                })
            }
        prefs.edit().putString(KEY_RULES_JSON, arr.toString()).commit()
    }

    private fun parseJson(json: String): List<Rule> = runCatching {
        val arr = JSONArray(json)
        buildList {
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                val uid = o.optInt("uid", -1)
                val protocol = o.optString("protocol", "TCP").uppercase()
                val start = o.optInt("start", -1)
                val end = o.optInt("end", start)
                if (uid >= GLOBAL_UID && (protocol == "TCP" || protocol == "UDP") && start in 1..65535 && end in start..65535) {
                    add(Rule(uid, protocol, start, end, o.optBoolean("allowed", false)))
                }
            }
        }.sortedWith(compareBy<Rule> { it.uid }.thenBy { it.protocol }.thenBy { it.startPort }.thenBy { it.endPort })
    }.getOrDefault(emptyList())

}
