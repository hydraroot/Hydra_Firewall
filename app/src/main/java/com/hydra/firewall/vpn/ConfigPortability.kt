package com.hydra.firewall.vpn

/**
 * Exportar / importar la configuración de Hydra de forma PORTABLE (lógica pura, sin Android).
 *
 * Problema que resuelve: las reglas por app se guardan por UID (`uid_10123_wifi`), y el UID cambia entre
 * celulares y al reinstalar apps. Aplicar un UID viejo daría permisos a OTRA app. Por eso el archivo guarda
 * el NOMBRE DE PAQUETE y al importar se traduce al UID actual de ese paquete.
 *
 * Qué NO se exporta nunca: PIN/huella (`firewall_lock`), historial, estadísticas, estado del servicio,
 * decisiones temporales, cuarentena pendiente, claves de firmas ni listas descargadas.
 * Qué NO se importa nunca aunque el archivo lo traiga: `invalid_uid_allowed` (abre el firewall ante UID
 * desconocido) — esa decisión de seguridad queda siempre en el dispositivo.
 */
object ConfigPortability {
    const val FORMAT = "hydra-config"
    const val VERSION = 1
    const val MAX_BYTES = 4_000_000

    const val PREF_RULES = "firewall_rules"
    const val PREF_PROTECTION = "hydra_custom_protection_profiles"
    const val PREF_ADVANCED = "firewall_advanced_rules"
    const val PREF_IPS = "firewall_ips"
    const val PREF_SETTINGS = "firewall_settings"
    const val PREF_COMPAT = "app_compatibility_policy"
    const val PREF_CUSTOM_DOMAINS = "hydra_custom_domain_rules"
    const val PREF_DOMAIN_BLOCK = "firewall_domain_block"
    /** Contiene `essential_uids` (apps Esenciales elegidas por el usuario, por UID). Solo esa clave viaja, por paquete. */
    const val PREF_APP_PREFS = "hydra_app_prefs"

    const val KEY_RULES_JSON = "rules_json"
    const val KEY_BLOCKED_IPS = "blocked_ips"
    const val KEY_ALLOWED_UID_IPS = "allowed_uid_ips"
    const val KEY_DOMAIN_BLOCK_ENABLED = "domain_block_enabled"
    const val KEY_ESSENTIAL_UIDS = "essential_uids"

    /** Archivos de preferencias que se leen para exportar (el resto de la app no se toca). */
    val EXPORTED_PREFS: List<String> = listOf(
        PREF_RULES, PREF_PROTECTION, PREF_ADVANCED, PREF_IPS,
        PREF_SETTINGS, PREF_COMPAT, PREF_CUSTOM_DOMAINS, PREF_DOMAIN_BLOCK, PREF_APP_PREFS
    )

    private val UID_KEY = Regex("^uid_(\\d{1,10})_([a-z0-9_]{1,60})$")
    private val SAFE_KEY = Regex("^[A-Za-z0-9_.:\\-]{1,160}$")
    private val SAFE_PACKAGE = Regex("^[A-Za-z0-9_.]{1,200}$")
    private val SAFE_IP = Regex("^[0-9A-Fa-f:.]{2,45}$")
    private val SAFE_PROTOCOL = Regex("^[A-Z0-9]{1,8}$")
    private val NEVER_IMPORT = setOf("invalid_uid_allowed")
    private const val FIRST_APP_UID = 10000
    private const val MAX_STRING = 200_000
    private const val MAX_SET = 100_000

    private fun isTemporarySuffix(s: String) = s.startsWith("temp_") || s == "quarantine_default"

    class ConfigFormatException(message: String) : Exception(message)

    data class Meta(val createdAt: Long, val appVersion: String, val applicationId: String)

    data class ExportStats(val apps: Int, val globalKeys: Int, val advancedRules: Int, val ipExceptions: Int, val orphanUids: Int)
    data class ExportResult(val json: String, val stats: ExportStats)

    data class AdvRule(val app: String, val protocol: String, val start: Int, val end: Int, val allowed: Boolean)

    data class ParsedConfig(
        val createdAt: Long,
        val appVersion: String,
        val source: String,
        val global: Map<String, Map<String, Any?>>,
        val apps: Map<String, Map<String, Map<String, Any?>>>,
        val advanced: List<AdvRule>,
        val ipExceptions: List<Pair<String, String>>,
        /** Paquetes marcados como Esenciales; null = el archivo no trae la sección (exportado por una versión anterior). */
        val essentialApps: List<String>? = null
    )

    data class ImportReport(
        val appsApplied: Int,
        val appsMissing: List<String>,
        val globalKeys: Int,
        val advancedApplied: Int,
        val advancedSkipped: Int,
        val ipApplied: Int,
        val ipSkipped: Int,
        val ignoredKeys: List<String>,
        val essentialApplied: Int = 0
    )

    data class ImportPlan(
        val removeKeys: Map<String, Set<String>>,
        val put: Map<String, Map<String, Any?>>,
        val report: ImportReport
    )

    // ------------------------------------------------------------------------------------- tipos

    internal fun encodeValue(v: Any?): Any? = when (v) {
        is Boolean, is String -> v
        is Int -> mapOf("int" to v.toLong())
        is Long -> mapOf("long" to v)
        is Float -> mapOf("float" to v.toDouble())
        is Set<*> -> v.map { it.toString() }.sorted()
        else -> null
    }

    internal fun decodeValue(j: Any?): Any? = when (j) {
        is Boolean -> j
        is String -> if (j.length <= MAX_STRING) j else null
        is List<*> -> if (j.size <= MAX_SET && j.all { it is String && it.length <= 2_000 }) j.map { it as String }.toSet() else null
        is Map<*, *> -> {
            if (j.size != 1) null else when (j.keys.first()) {
                "int" -> (j["int"] as? Long)?.takeIf { it in Int.MIN_VALUE..Int.MAX_VALUE }?.toInt()
                "long" -> j["long"] as? Long
                "float" -> (j["float"] as? Number)?.toFloat()?.takeIf { !it.isNaN() && !it.isInfinite() }
                else -> null
            }
        }
        else -> null
    }

    // ----------------------------------------------------------------------------------- exportar

    /**
     * @param snapshot nombre de prefs -> (clave -> valor) tal como lo devuelve SharedPreferences.all
     * @param packagesForUid paquetes que comparten ese UID en este dispositivo (vacío = huérfano)
     */
    fun export(
        snapshot: Map<String, Map<String, Any?>>,
        packagesForUid: (Int) -> List<String>,
        meta: Meta
    ): ExportResult {
        val global = linkedMapOf<String, Map<String, Any?>>()
        val apps = sortedMapOf<String, MutableMap<String, MutableMap<String, Any?>>>()
        val orphans = mutableSetOf<Int>()

        fun owners(uid: Int): List<String> {
            if (uid in 0 until FIRST_APP_UID) return listOf("aid:$uid")
            val pk = packagesForUid(uid).filter { SAFE_PACKAGE.matches(it) }.sorted()
            if (pk.isEmpty()) orphans += uid
            return pk
        }

        fun addGlobal(pref: String, key: String, value: Any?) {
            val enc = encodeValue(value) ?: return
            @Suppress("UNCHECKED_CAST")
            (global.getOrPut(pref) { sortedMapOf<String, Any?>() } as MutableMap<String, Any?>)[key] = enc
        }

        for ((pref, values) in snapshot) {
            if (pref !in EXPORTED_PREFS) continue
            for ((key, value) in values) {
                if (key in NEVER_IMPORT) continue
                when (pref) {
                    PREF_RULES, PREF_PROTECTION -> {
                        val m = UID_KEY.matchEntire(key)
                        if (m != null) {
                            val suffix = m.groupValues[2]
                            if (isTemporarySuffix(suffix)) continue
                            val enc = encodeValue(value) ?: continue
                            val uid = m.groupValues[1].toLongOrNull()?.takeIf { it <= Int.MAX_VALUE }?.toInt() ?: continue
                            for (pkg in owners(uid)) {
                                apps.getOrPut(pkg) { sortedMapOf() }.getOrPut(pref) { sortedMapOf() }[suffix] = enc
                            }
                        } else if (SAFE_KEY.matches(key)) addGlobal(pref, key, value)
                    }
                    PREF_ADVANCED, PREF_IPS -> Unit // se tratan abajo (llevan UID dentro del valor)
                    PREF_DOMAIN_BLOCK -> if (key == KEY_DOMAIN_BLOCK_ENABLED) addGlobal(pref, key, value)
                    PREF_APP_PREFS -> Unit // solo essential_uids, tratado abajo
                    else -> if (SAFE_KEY.matches(key)) addGlobal(pref, key, value)
                }
            }
        }

        // IPs bloqueadas (globales) y excepciones por app ("uid|ip")
        val ips = snapshot[PREF_IPS].orEmpty()
        (ips[KEY_BLOCKED_IPS] as? Set<*>)?.let { addGlobal(PREF_IPS, KEY_BLOCKED_IPS, it) }
        val ipExceptions = sortedSetOf<String>()
        for (entry in (ips[KEY_ALLOWED_UID_IPS] as? Set<*>).orEmpty()) {
            val s = entry.toString()
            val bar = s.indexOf('|')
            if (bar <= 0) continue
            val uid = s.substring(0, bar).toIntOrNull() ?: continue
            val ip = s.substring(bar + 1)
            if (!SAFE_IP.matches(ip)) continue
            for (pkg in owners(uid)) ipExceptions += "$pkg|$ip"
        }

        // Apps Esenciales elegidas por el usuario (UID -> paquete)
        val essential = sortedSetOf<String>()
        for (entry in (snapshot[PREF_APP_PREFS].orEmpty()[KEY_ESSENTIAL_UIDS] as? Set<*>).orEmpty()) {
            val uid = entry.toString().toIntOrNull() ?: continue
            for (pkg in owners(uid)) essential += pkg
        }

        // Reglas avanzadas (JSON con uid dentro)
        val advanced = mutableListOf<Map<String, Any?>>()
        val rawAdv = snapshot[PREF_ADVANCED].orEmpty()[KEY_RULES_JSON] as? String
        if (rawAdv != null) {
            val arr = runCatching { MiniJson.parse(rawAdv) as? List<*> }.getOrNull().orEmpty()
            for (o in arr) {
                val m = o as? Map<*, *> ?: continue
                val uid = (m["uid"] as? Number)?.toLong()?.toInt() ?: continue
                val protocol = (m["protocol"] as? String)?.uppercase() ?: continue
                val start = (m["start"] as? Number)?.toInt() ?: continue
                val end = (m["end"] as? Number)?.toInt() ?: continue
                val allowed = m["allowed"] as? Boolean ?: continue
                val targets = if (uid == -1) listOf("*") else owners(uid)
                for (t in targets) advanced += linkedMapOf(
                    "app" to t, "protocol" to protocol, "start" to start.toLong(), "end" to end.toLong(), "allowed" to allowed
                )
            }
        }
        advanced.sortWith(compareBy({ it["app"] as String }, { it["protocol"] as String }, { it["start"] as Long }))

        val root = linkedMapOf<String, Any?>(
            "format" to FORMAT,
            "version" to VERSION.toLong(),
            "created_at" to meta.createdAt,
            "app_version" to meta.appVersion,
            "source_application_id" to meta.applicationId,
            "global" to global,
            "apps" to apps,
            "advanced_rules" to advanced,
            "ip_exceptions" to ipExceptions.toList(),
            "essential_apps" to essential.toList()
        )
        val stats = ExportStats(
            apps = apps.size,
            globalKeys = global.values.sumOf { it.size },
            advancedRules = advanced.size,
            ipExceptions = ipExceptions.size,
            orphanUids = orphans.size
        )
        return ExportResult(MiniJson.write(root, pretty = true), stats)
    }

    // ------------------------------------------------------------------------------------ importar

    fun parse(text: String): ParsedConfig {
        if (text.length > MAX_BYTES) throw ConfigFormatException("El archivo es demasiado grande")
        val root = try {
            MiniJson.parse(text) as? Map<*, *> ?: throw ConfigFormatException("El archivo no es una configuración de Hydra")
        } catch (e: IllegalArgumentException) {
            throw ConfigFormatException("El archivo no es un JSON válido")
        }
        if (root["format"] != FORMAT) throw ConfigFormatException("El archivo no es una configuración de Hydra")
        val version = (root["version"] as? Long) ?: throw ConfigFormatException("Falta la versión del archivo")
        if (version < 1 || version > VERSION) throw ConfigFormatException("Versión de archivo no soportada ($version)")

        val global = linkedMapOf<String, Map<String, Any?>>()
        for ((pref, vals) in (root["global"] as? Map<*, *>).orEmpty()) {
            if (pref !is String || pref !in EXPORTED_PREFS || vals !is Map<*, *>) continue
            val dec = linkedMapOf<String, Any?>()
            for ((k, v) in vals) {
                if (k is String) decodeValue(v)?.let { dec[k] = it }
            }
            global[pref] = dec
        }

        val apps = linkedMapOf<String, Map<String, Map<String, Any?>>>()
        for ((pkg, perPref) in (root["apps"] as? Map<*, *>).orEmpty()) {
            if (pkg !is String || perPref !is Map<*, *>) continue
            if (!(SAFE_PACKAGE.matches(pkg) || (pkg.startsWith("aid:") && pkg.drop(4).toIntOrNull() != null))) continue
            val prefs = linkedMapOf<String, Map<String, Any?>>()
            for ((pref, vals) in perPref) {
                if (pref !is String || (pref != PREF_RULES && pref != PREF_PROTECTION) || vals !is Map<*, *>) continue
                val dec = linkedMapOf<String, Any?>()
                for ((suffix, v) in vals) {
                    if (suffix is String && Regex("^[a-z0-9_]{1,60}$").matches(suffix)) decodeValue(v)?.let { dec[suffix] = it }
                }
                prefs[pref] = dec
            }
            apps[pkg] = prefs
        }

        val adv = mutableListOf<AdvRule>()
        for (o in (root["advanced_rules"] as? List<*>).orEmpty()) {
            val m = o as? Map<*, *> ?: continue
            adv += AdvRule(
                app = m["app"] as? String ?: continue,
                protocol = (m["protocol"] as? String)?.uppercase() ?: continue,
                start = (m["start"] as? Long)?.toInt() ?: continue,
                end = (m["end"] as? Long)?.toInt() ?: continue,
                allowed = m["allowed"] as? Boolean ?: continue
            )
        }

        val ips = mutableListOf<Pair<String, String>>()
        for (e in (root["ip_exceptions"] as? List<*>).orEmpty()) {
            val s = e as? String ?: continue
            val bar = s.indexOf('|')
            if (bar > 0) ips += s.substring(0, bar) to s.substring(bar + 1)
        }

        val essentialApps = if (root.containsKey("essential_apps")) {
            (root["essential_apps"] as? List<*>).orEmpty()
                .mapNotNull { it as? String }
                .filter { SAFE_PACKAGE.matches(it) }
                .distinct()
        } else null

        return ParsedConfig(
            createdAt = root["created_at"] as? Long ?: 0L,
            appVersion = (root["app_version"] as? String).orEmpty().take(64),
            source = (root["source_application_id"] as? String).orEmpty().take(128),
            global = global, apps = apps, advanced = adv, ipExceptions = ips, essentialApps = essentialApps
        )
    }

    /**
     * Calcula los cambios a aplicar SIN escribir nada (permite mostrar un resumen antes de confirmar).
     * Semántica: REEMPLAZA reglas por app, reglas avanzadas y excepciones de IP; las claves globales del archivo
     * se sobrescriben y las que el archivo no trae quedan como están.
     *
     * @param current estado actual de las prefs (para saber qué claves por UID hay que limpiar)
     * @param uidForPackage UID actual del paquete, o null si no está instalado
     */
    fun plan(
        parsed: ParsedConfig,
        current: Map<String, Map<String, Any?>>,
        uidForPackage: (String) -> Int?
    ): ImportPlan {
        val remove = linkedMapOf<String, MutableSet<String>>()
        val put = linkedMapOf<String, MutableMap<String, Any?>>()
        val ignored = mutableListOf<String>()
        var globalCount = 0

        fun putKey(pref: String, key: String, value: Any?) { put.getOrPut(pref) { linkedMapOf() }[key] = value }

        // 1) globales
        for ((pref, vals) in parsed.global) {
            for ((key, value) in vals) {
                if (key in NEVER_IMPORT) { ignored += "$pref/$key"; continue }
                if (!SAFE_KEY.matches(key)) { ignored += "$pref/$key"; continue }
                val allowed = when (pref) {
                    PREF_RULES, PREF_PROTECTION -> !UID_KEY.matches(key)          // un UID suelto jamás entra como "global"
                    PREF_DOMAIN_BLOCK -> key == KEY_DOMAIN_BLOCK_ENABLED && value is Boolean
                    PREF_IPS -> key == KEY_BLOCKED_IPS && value is Set<*>
                    PREF_ADVANCED -> false
                    PREF_APP_PREFS -> false      // solo se escribe essential_uids, traducido desde paquetes
                    else -> true
                }
                if (!allowed) { ignored += "$pref/$key"; continue }
                putKey(pref, key, value)
                globalCount++
            }
        }

        // 2) reglas por app: se limpian las claves por UID actuales y se escriben las traducidas
        for (pref in listOf(PREF_RULES, PREF_PROTECTION)) {
            val stale = current[pref].orEmpty().keys.filter { UID_KEY.matches(it) }
            if (stale.isNotEmpty()) remove.getOrPut(pref) { linkedSetOf() }.addAll(stale)
        }
        val missing = linkedSetOf<String>()
        val applied = linkedSetOf<String>()
        fun resolve(pkg: String): Int? = when {
            pkg.startsWith("aid:") -> pkg.drop(4).toIntOrNull()?.takeIf { it in 0 until FIRST_APP_UID }
            else -> uidForPackage(pkg)
        }
        for ((pkg, perPref) in parsed.apps) {
            val uid = resolve(pkg)
            if (uid == null) { missing += pkg; continue }
            var any = false
            for ((pref, vals) in perPref) {
                for ((suffix, value) in vals) {
                    if (isTemporarySuffix(suffix)) continue
                    putKey(pref, "uid_${uid}_$suffix", value)
                    any = true
                }
            }
            if (any) applied += pkg
        }

        // 3) reglas avanzadas (reemplazo completo)
        val advOut = mutableListOf<Map<String, Any?>>()
        var advSkipped = 0
        for (r in parsed.advanced) {
            val uid = if (r.app == "*") -1 else resolve(r.app)
            if (uid == null || !SAFE_PROTOCOL.matches(r.protocol)) { advSkipped++; continue }
            val s = r.start.coerceIn(1, 65535)
            val e = r.end.coerceIn(s, 65535)
            advOut += linkedMapOf<String, Any?>(
                "uid" to uid.toLong(), "protocol" to r.protocol, "start" to s.toLong(), "end" to e.toLong(), "allowed" to r.allowed
            )
        }
        val deduped = advOut.distinctBy { "${it["uid"]}:${it["protocol"]}:${it["start"]}:${it["end"]}" }
            .sortedWith(compareBy({ it["uid"] as Long }, { it["protocol"] as String }, { it["start"] as Long }, { it["end"] as Long }))
        putKey(PREF_ADVANCED, KEY_RULES_JSON, MiniJson.write(deduped))

        // 4) excepciones de IP por app (reemplazo completo)
        val ipOut = linkedSetOf<String>()
        var ipSkipped = 0
        for ((pkg, ip) in parsed.ipExceptions) {
            val uid = resolve(pkg)
            if (uid == null || !SAFE_IP.matches(ip)) { ipSkipped++; continue }
            ipOut += "$uid|$ip"
        }
        putKey(PREF_IPS, KEY_ALLOWED_UID_IPS, ipOut.toSet())

        // 5) apps Esenciales (reemplazo completo, solo si el archivo trae la sección)
        var essentialCount = 0
        parsed.essentialApps?.let { pkgs ->
            val uids = linkedSetOf<String>()
            for (pkg in pkgs) resolve(pkg)?.let { uids += it.toString() }
            putKey(PREF_APP_PREFS, KEY_ESSENTIAL_UIDS, uids.toSet())
            essentialCount = uids.size
        }

        return ImportPlan(
            removeKeys = remove,
            put = put,
            report = ImportReport(
                appsApplied = applied.size,
                appsMissing = missing.toList(),
                globalKeys = globalCount,
                advancedApplied = deduped.size,
                advancedSkipped = advSkipped,
                ipApplied = ipOut.size,
                ipSkipped = ipSkipped,
                ignoredKeys = ignored,
                essentialApplied = essentialCount
            )
        )
    }
}
