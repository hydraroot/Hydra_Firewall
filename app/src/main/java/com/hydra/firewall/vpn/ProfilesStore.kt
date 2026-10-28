package com.hydra.firewall.vpn

import android.content.Context
import org.json.JSONObject

class ProfilesStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("firewall_profiles", Context.MODE_PRIVATE)
    fun names(): List<String> = prefs.all.keys.sorted()
    fun save(name: String, snapshot: String) { if (name.isNotBlank()) prefs.edit().putString(name.trim(), snapshot).apply() }
    fun load(name: String): String? = prefs.getString(name, null)
    fun delete(name: String) = prefs.edit().remove(name).apply()
}

fun resetRulesToDefaults(store: RuleStore, advanced: AdvancedRuleStore, ipBlocks: IpBlockStore) {
    store.clearRules()
    advanced.clearAll()
    ipBlocks.clear()
    store.policyMode = "BLACKLIST"
    store.defaultWifiAllowed = false
    store.defaultMobileAllowed = false
    store.askOnFirstConnection = true
    store.allowLocalNetwork = true
    store.blockWhenRoaming = false
    store.blockWhenScreenOff = false
    store.globalBlockAll = false
    store.secureDnsEnabled = true
    store.invalidUidAllowed = false
}


fun exportRuleSnapshot(store: RuleStore, advanced: AdvancedRuleStore): String {
    val root = JSONObject()
    root.put("policyMode", store.policyMode)
    root.put("defaultWifiAllowed", store.defaultWifiAllowed)
    root.put("defaultMobileAllowed", store.defaultMobileAllowed)
    root.put("askOnFirstConnection", store.askOnFirstConnection)
    root.put("learningMode", store.learningMode)
    root.put("allowLocalNetwork", store.allowLocalNetwork)
    root.put("blockWhenRoaming", store.blockWhenRoaming)
    root.put("blockWhenScreenOff", store.blockWhenScreenOff)
    root.put("secureDnsEnabled", store.secureDnsEnabled)
    root.put("globalBlockAll", store.globalBlockAll)
    val rules = org.json.JSONArray()
    store.ruleSnapshotEntries().forEach { e ->
        rules.put(JSONObject().apply { put("uid", e.uid); put("wifi", e.wifiAllowed); put("mobile", e.mobileAllowed); put("schedule", e.scheduleEnabled); put("start", e.startMinutes); put("end", e.endMinutes); put("days", e.daysMask) })
    }
    root.put("rules", rules)
    val adv = org.json.JSONArray()
    advanced.getAll().forEach { r -> adv.put(JSONObject().apply { put("uid", r.uid); put("protocol", r.protocol); put("start", r.startPort); put("end", r.endPort); put("allowed", r.allowed) }) }
    root.put("advanced", adv)
    return root.toString()
}



data class ProfileSummary(
    val policyMode: String,
    val defaultWifiAllowed: Boolean,
    val defaultMobileAllowed: Boolean,
    val appRuleCount: Int,
    val wifiBlockedCount: Int,
    val mobileBlockedCount: Int,
    val scheduleCount: Int,
    val advancedRuleCount: Int,
    val advancedBlockCount: Int,
    val advancedAllowCount: Int,
    val advancedRules: List<Triple<String, String, String>>
)

fun profileSummary(json: String, appName: (Int) -> String): ProfileSummary {
    val root = JSONObject(json)
    val rules = root.optJSONArray("rules") ?: org.json.JSONArray()
    var wifiBlocked = 0
    var mobileBlocked = 0
    var schedules = 0
    for (i in 0 until rules.length()) {
        val o = rules.optJSONObject(i) ?: continue
        if (!o.optBoolean("wifi", true)) wifiBlocked++
        if (!o.optBoolean("mobile", true)) mobileBlocked++
        if (o.optBoolean("schedule", false)) schedules++
    }
    val adv = root.optJSONArray("advanced") ?: org.json.JSONArray()
    val details = mutableListOf<Triple<String, String, String>>()
    var advBlock = 0
    var advAllow = 0
    for (i in 0 until adv.length()) {
        val o = adv.optJSONObject(i) ?: continue
        val uid = o.optInt("uid", -1)
        val protocol = o.optString("protocol", "TCP")
        val start = o.optInt("start", 443)
        val end = o.optInt("end", start)
        val allowed = o.optBoolean("allowed", false)
        if (allowed) advAllow++ else advBlock++
        val port = if (start == end) start.toString() else "$start-$end"
        details += Triple(appName(uid), "$protocol $port", if (allowed) "ALLOW" else "BLOCK")
    }
    return ProfileSummary(
        policyMode = root.optString("policyMode", "BLACKLIST"),
        defaultWifiAllowed = root.optBoolean("defaultWifiAllowed", false),
        defaultMobileAllowed = root.optBoolean("defaultMobileAllowed", false),
        appRuleCount = rules.length(),
        wifiBlockedCount = wifiBlocked,
        mobileBlockedCount = mobileBlocked,
        scheduleCount = schedules,
        advancedRuleCount = adv.length(),
        advancedBlockCount = advBlock,
        advancedAllowCount = advAllow,
        advancedRules = details
    )
}

fun importRuleSnapshot(store: RuleStore, advanced: AdvancedRuleStore, json: String) {
    val root = JSONObject(json)
    store.clearRules()
    advanced.getAll().forEach { advanced.remove(it) }
    store.policyMode = root.optString("policyMode", "BLACKLIST")
    store.defaultWifiAllowed = root.optBoolean("defaultWifiAllowed", false)
    store.defaultMobileAllowed = root.optBoolean("defaultMobileAllowed", false)
    store.askOnFirstConnection = root.optBoolean("askOnFirstConnection", true)
    store.learningMode = root.optBoolean("learningMode", false)
    store.allowLocalNetwork = root.optBoolean("allowLocalNetwork", true)
    store.blockWhenRoaming = root.optBoolean("blockWhenRoaming", false)
    store.blockWhenScreenOff = root.optBoolean("blockWhenScreenOff", false)
    store.globalBlockAll = root.optBoolean("globalBlockAll", false)
    store.secureDnsEnabled = root.optBoolean("secureDnsEnabled", true)
    val rules = root.optJSONArray("rules") ?: org.json.JSONArray()
    for (i in 0 until rules.length()) {
        val o = rules.optJSONObject(i) ?: continue
        val uid = o.optInt("uid", -1); if (uid < 0) continue
        store.setWifiAllowed(uid, o.optBoolean("wifi", true)); store.setMobileAllowed(uid, o.optBoolean("mobile", true))
        store.setSchedule(uid, RuleStore.Schedule(o.optBoolean("schedule", false), o.optInt("start", 1320), o.optInt("end", 420), o.optInt("days", 127)))
    }
    val adv = root.optJSONArray("advanced") ?: org.json.JSONArray()
    for (i in 0 until adv.length()) {
        val o = adv.optJSONObject(i) ?: continue
        advanced.set(o.optInt("uid", -1), o.optString("protocol", "TCP"), o.optInt("start", 443), o.optInt("end", 443), o.optBoolean("allowed", false))
    }
}
