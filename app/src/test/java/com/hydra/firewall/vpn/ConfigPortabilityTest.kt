package com.hydra.firewall.vpn

import com.hydra.firewall.vpn.ConfigPortability as CP
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ConfigPortabilityTest {
    private val meta = CP.Meta(createdAt = 1_700_000_000_000L, appVersion = "1.5-test", applicationId = "com.hydraroot.firewall")

    // Celular A: banco=10123, chat=10200, dos apps con UID compartido=10300, huérfano=10999
    private val packagesA = mapOf(
        10123 to listOf("com.bank.app"), 10200 to listOf("com.chat.app"),
        10300 to listOf("com.shared.one", "com.shared.two")
    )

    private fun snapshotA(): Map<String, Map<String, Any?>> = mapOf(
        CP.PREF_RULES to mapOf(
            "uid_10123_wifi" to true, "uid_10123_mobile" to false,
            "uid_10123_schedule_enabled" to true, "uid_10123_schedule_start" to 1320,
            "uid_10123_temp_expires" to 9_999_999_999L,        // temporal: no se exporta
            "uid_10200_wifi" to false, "uid_10200_quarantine_default" to true, // cuarentena: no se exporta
            "uid_10300_wifi" to true, "uid_10300_mobile" to true,
            "uid_10999_wifi" to true,                           // huérfano
            "uid_1000_wifi" to true,                            // UID de sistema
            "policy_mode" to "BLACKLIST", "ask_first" to true,
            "invalid_uid_allowed" to true                        // jamás se exporta
        ),
        CP.PREF_PROTECTION to mapOf("uid_10123_sni" to true, "uid_10123_quic" to false),
        CP.PREF_ADVANCED to mapOf(CP.KEY_RULES_JSON to MiniJson.write(listOf(
            mapOf("uid" to 10123L, "protocol" to "TCP", "start" to 443L, "end" to 443L, "allowed" to true),
            mapOf("uid" to -1L, "protocol" to "UDP", "start" to 53L, "end" to 53L, "allowed" to false),
            mapOf("uid" to 10999L, "protocol" to "TCP", "start" to 80L, "end" to 80L, "allowed" to true)
        ))),
        CP.PREF_IPS to mapOf(
            CP.KEY_BLOCKED_IPS to setOf("1.2.3.4", "10.0.0.0/8"),
            CP.KEY_ALLOWED_UID_IPS to setOf("10200|192.168.1.1", "10999|8.8.8.8")
        ),
        CP.PREF_SETTINGS to mapOf("language" to "ES", "ui_refresh_seconds" to 3, "show_system_apps" to false),
        CP.PREF_COMPAT to mapOf("mode_com.bank.app" to "ESSENTIAL"),
        CP.PREF_CUSTOM_DOMAINS to mapOf("rules" to "[{\"d\":\"x.com\"}]"),
        CP.PREF_DOMAIN_BLOCK to mapOf(CP.KEY_DOMAIN_BLOCK_ENABLED to true, "active_list_count" to 80000, "blocked_today_count" to 5L),
        "firewall_lock" to mapOf("pin_hash" to "SECRETO", "enabled" to true),     // jamás
        "firewall_history" to mapOf("x" to "y")
    )

    private fun export() = CP.export(snapshotA(), { packagesA[it].orEmpty() }, meta)

    @Test
    fun exportUsesPackageNamesAndSkipsSensitiveOrTemporaryData() {
        val r = export()
        val j = r.json
        assertTrue(j.contains("com.bank.app") && j.contains("com.chat.app"))
        assertFalse("PIN filtrado", j.contains("SECRETO") || j.contains("pin_hash") || j.contains("firewall_lock"))
        assertFalse("invalid_uid_allowed no debe salir", j.contains("invalid_uid_allowed"))
        assertFalse("temporales fuera", j.contains("temp_expires"))
        assertFalse("cuarentena fuera", j.contains("quarantine_default"))
        assertFalse("historial fuera", j.contains("firewall_history"))
        assertFalse("contadores diarios fuera", j.contains("blocked_today_count") || j.contains("active_list_count"))
        assertFalse("no deben aparecer UIDs de apps", j.contains("10123") || j.contains("uid_1"))
        assertEquals(1, r.stats.orphanUids) // 10999 huérfano (aparece en reglas, avanzadas e IPs pero cuenta una vez)
    }

    @Test
    fun sharedUidIsExportedUnderEveryPackage() {
        val parsed = CP.parse(export().json)
        assertEquals(true, parsed.apps["com.shared.one"]!![CP.PREF_RULES]!!["wifi"])
        assertEquals(true, parsed.apps["com.shared.two"]!![CP.PREF_RULES]!!["wifi"])
    }

    @Test
    fun systemUidsUseAidPlaceholder() {
        val parsed = CP.parse(export().json)
        assertEquals(true, parsed.apps["aid:1000"]!![CP.PREF_RULES]!!["wifi"])
    }

    @Test
    fun importTranslatesPackagesToTheNewDevicesUids() {
        // Celular B: mismas apps pero con UIDs distintos; falta la app de chat
        val uidsB = mapOf("com.bank.app" to 10555, "com.shared.one" to 10600, "com.shared.two" to 10600)
        val currentB = mapOf(CP.PREF_RULES to mapOf<String, Any?>("uid_10555_wifi" to false, "uid_10777_wifi" to true, "ask_first" to false))
        val plan = CP.plan(CP.parse(export().json), currentB) { uidsB[it] }

        val rules = plan.put[CP.PREF_RULES]!!
        assertEquals(true, rules["uid_10555_wifi"])
        assertEquals(false, rules["uid_10555_mobile"])
        assertEquals(true, rules["uid_10555_schedule_enabled"])
        assertEquals(1320, rules["uid_10555_schedule_start"])          // Int sigue siendo Int
        assertEquals(true, rules["uid_10600_wifi"])
        assertEquals("BLACKLIST", rules["policy_mode"])                 // global
        assertFalse("UIDs del celular A no deben aparecer", rules.keys.any { it.contains("10123") || it.contains("10200") })
        assertEquals(setOf("uid_10555_wifi", "uid_10777_wifi"), plan.removeKeys[CP.PREF_RULES])   // limpia lo viejo por UID
        assertFalse("no borra globales", plan.removeKeys[CP.PREF_RULES]!!.contains("ask_first"))
        assertEquals(listOf("com.chat.app"), plan.report.appsMissing)
        assertEquals(4, plan.report.appsApplied) // bank + shared.one + shared.two + aid:1000
    }

    @Test
    fun protectionProfilesAndCompatTravelByPackage() {
        val plan = CP.plan(CP.parse(export().json), emptyMap()) { if (it == "com.bank.app") 10555 else null }
        assertEquals(true, plan.put[CP.PREF_PROTECTION]!!["uid_10555_sni"])
        assertEquals("ESSENTIAL", plan.put[CP.PREF_COMPAT]!!["mode_com.bank.app"])
    }

    @Test
    fun advancedRulesAndIpExceptionsAreRemappedAndOrphansDropped() {
        val plan = CP.plan(CP.parse(export().json), emptyMap()) { if (it == "com.bank.app") 10555 else if (it == "com.chat.app") 10666 else null }
        val adv = MiniJson.parse(plan.put[CP.PREF_ADVANCED]!![CP.KEY_RULES_JSON] as String) as List<*>
        val uids = adv.map { (it as Map<*, *>)["uid"] }
        assertEquals(listOf(-1L, 10555L), uids)                          // global -1 se conserva
        assertEquals(setOf("10666|192.168.1.1"), plan.put[CP.PREF_IPS]!![CP.KEY_ALLOWED_UID_IPS])
        assertEquals(setOf("1.2.3.4", "10.0.0.0/8"), plan.put[CP.PREF_IPS]!![CP.KEY_BLOCKED_IPS])
    }

    @Test
    fun importNeverAppliesInvalidUidAllowedEvenIfFileCarriesIt() {
        val hostile = """{"format":"hydra-config","version":1,"global":{"firewall_rules":{"invalid_uid_allowed":true,"ask_first":false}}}"""
        val plan = CP.plan(CP.parse(hostile), emptyMap()) { null }
        assertNull(plan.put[CP.PREF_RULES]!!["invalid_uid_allowed"])
        assertEquals(false, plan.put[CP.PREF_RULES]!!["ask_first"])
        assertTrue(plan.report.ignoredKeys.contains("firewall_rules/invalid_uid_allowed"))
    }

    @Test
    fun hostileFileCannotSmuggleUidKeysUnknownPrefsOrOtherDomainKeys() {
        val hostile = """{
          "format":"hydra-config","version":1,
          "global":{
            "firewall_rules":{"uid_5_wifi":true,"ok_key":true,"bad key!":true},
            "firewall_lock":{"enabled":false},
            "firewall_domain_block":{"domain_block_enabled":true,"active_list_source":"x"},
            "firewall_ips":{"blocked_ips":["9.9.9.9"],"allowed_uid_ips":["1|1.1.1.1"]}
          },
          "apps":{"../../etc/passwd":{"firewall_rules":{"wifi":true}},"com.ok.app":{"firewall_lock":{"x":true},"firewall_rules":{"wifi":true,"Bad Suffix":true}}}
        }"""
        val plan = CP.plan(CP.parse(hostile), emptyMap()) { if (it == "com.ok.app") 10001 else null }
        assertNull(plan.put["firewall_lock"])
        assertFalse(plan.put[CP.PREF_RULES]!!.containsKey("uid_5_wifi"))
        assertFalse(plan.put[CP.PREF_RULES]!!.containsKey("bad key!"))
        assertEquals(true, plan.put[CP.PREF_RULES]!!["ok_key"])
        assertEquals(setOf(CP.KEY_DOMAIN_BLOCK_ENABLED), plan.put[CP.PREF_DOMAIN_BLOCK]!!.keys)
        assertEquals(setOf("9.9.9.9"), plan.put[CP.PREF_IPS]!![CP.KEY_BLOCKED_IPS])
        assertEquals(emptySet<String>(), plan.put[CP.PREF_IPS]!![CP.KEY_ALLOWED_UID_IPS])   // la excepción global se ignora
        assertEquals(true, plan.put[CP.PREF_RULES]!!["uid_10001_wifi"])
        assertFalse(plan.put[CP.PREF_RULES]!!.containsKey("uid_10001_Bad Suffix"))
        assertFalse(plan.put[CP.PREF_RULES]!!.keys.any { it.contains("passwd") })
    }

    @Test
    fun roundTripOnSameDeviceReproducesTheSameRules() {
        val uidOf = packagesA.flatMap { (uid, pk) -> pk.map { it to uid } }.toMap()
        val plan = CP.plan(CP.parse(export().json), snapshotA()) { uidOf[it] }
        val rules = plan.put[CP.PREF_RULES]!!
        assertEquals(true, rules["uid_10123_wifi"])
        assertEquals(false, rules["uid_10123_mobile"])
        assertEquals(true, rules["uid_10300_wifi"])
        assertEquals(true, rules["uid_1000_wifi"])
        // el temporal y la cuarentena no vuelven
        assertFalse(rules.containsKey("uid_10123_temp_expires"))
        assertFalse(rules.containsKey("uid_10200_quarantine_default"))
        assertEquals("ES", plan.put[CP.PREF_SETTINGS]!!["language"])
        assertEquals(3, plan.put[CP.PREF_SETTINGS]!!["ui_refresh_seconds"])
    }

    @Test
    fun rejectsWrongFormatVersionAndOversizedFiles() {
        val bad = listOf("not json", "[]", """{"format":"otra-cosa","version":1}""", """{"format":"hydra-config"}""",
            """{"format":"hydra-config","version":99}""", """{"format":"hydra-config","version":0}""")
        for (b in bad) {
            try { CP.parse(b); fail("debía rechazar: $b") } catch (e: CP.ConfigFormatException) { /* ok */ }
        }
        try { CP.parse("x".repeat(CP.MAX_BYTES + 1)); fail("tamaño") } catch (e: CP.ConfigFormatException) { /* ok */ }
    }

    @Test
    fun valueTypesSurviveEncodeDecode() {
        val values = listOf<Any>(true, "texto", 7, 7L, 1.5f, setOf("a", "b"))
        for (v in values) assertEquals(v, CP.decodeValue(MiniJson.parse(MiniJson.write(CP.encodeValue(v)))))
        assertNull(CP.decodeValue(mapOf("int" to 99999999999L)))
        assertNull(CP.decodeValue(mapOf("raro" to 1L)))
        assertNull(CP.decodeValue(5L))
    }

    @Test
    fun advancedRulePortsAreClampedAndBadProtocolsSkipped() {
        val json = """{"format":"hydra-config","version":1,"advanced_rules":[
          {"app":"*","protocol":"tcp","start":0,"end":999999,"allowed":true},
          {"app":"*","protocol":"TCP; DROP","start":1,"end":2,"allowed":true}]}"""
        val plan = CP.plan(CP.parse(json), emptyMap()) { null }
        val adv = MiniJson.parse(plan.put[CP.PREF_ADVANCED]!![CP.KEY_RULES_JSON] as String) as List<*>
        assertEquals(1, adv.size)
        assertEquals(1L, (adv[0] as Map<*, *>)["start"])
        assertEquals(65535L, (adv[0] as Map<*, *>)["end"])
        assertEquals(1, plan.report.advancedSkipped)
    }

    // ---- Apps Esenciales (hydra_app_prefs/essential_uids) -------------------------------------------

    @Test
    fun essentialAppsTravelByPackageAndOnlyThatKeyIsExported() {
        val snap = snapshotA().toMutableMap()
        snap[CP.PREF_APP_PREFS] = mapOf(
            CP.KEY_ESSENTIAL_UIDS to setOf("10123", "10300", "10999", "abc"),
            "otra_cosa_privada" to "NO_SALE"
        )
        val r = CP.export(snap, { packagesA[it].orEmpty() }, meta)
        assertFalse(r.json.contains("NO_SALE") || r.json.contains("otra_cosa_privada"))
        val parsed = CP.parse(r.json)
        assertEquals(listOf("com.bank.app", "com.shared.one", "com.shared.two"), parsed.essentialApps)

        // Celular B: cambian los UID, y falta com.shared.two
        val uidsB = mapOf("com.bank.app" to 10777, "com.shared.one" to 10888)
        val plan = CP.plan(parsed, emptyMap()) { uidsB[it] }
        assertEquals(setOf("10777", "10888"), plan.put[CP.PREF_APP_PREFS]?.get(CP.KEY_ESSENTIAL_UIDS))
        assertEquals(2, plan.report.essentialApplied)
    }

    @Test
    fun oldExportWithoutEssentialSectionLeavesEssentialAppsUntouched() {
        val parsed = CP.parse(export().json.replace("\"essential_apps\"", "\"x_other\""))
        assertNull(parsed.essentialApps)
        val plan = CP.plan(parsed, emptyMap()) { null }
        assertNull(plan.put[CP.PREF_APP_PREFS])
    }

    @Test
    fun hostileFileCannotWriteArbitraryKeysIntoAppPrefs() {
        val hostile = """{"format":"hydra-config","version":1,"global":{"hydra_app_prefs":{"essential_uids":["1"],"evil":"x"}},"apps":{}}"""
        val plan = CP.plan(CP.parse(hostile), emptyMap()) { null }
        assertNull(plan.put[CP.PREF_APP_PREFS])
        assertTrue(plan.report.ignoredKeys.any { it.startsWith(CP.PREF_APP_PREFS) })
    }
}

