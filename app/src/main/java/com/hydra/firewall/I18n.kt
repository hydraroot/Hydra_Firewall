package com.hydra.firewall

import android.content.Context
import java.util.Locale

enum class AppLanguage { SYSTEM, ES, EN }

class AppSettings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("firewall_settings", Context.MODE_PRIVATE)

    init {
        if (!prefs.getBoolean("fix114_system_apps_migrated", false)) {
            // System applications stay hidden by default. The single control
            // for changing that lives in RULES; remove the old duplicate
            // Settings control and migrate the previous default-on state.
            prefs.edit()
                .putBoolean("show_system_apps", false)
                .putBoolean("fix114_system_apps_migrated", true)
                .apply()
        }
    }

    var advancedMode: Boolean get() = prefs.getBoolean("advanced_mode", false); set(value) = prefs.edit().putBoolean("advanced_mode", value).apply()
    var showSystemApps: Boolean get() = prefs.getBoolean("show_system_apps", false); set(value) = prefs.edit().putBoolean("show_system_apps", value).apply()
    var trustedAppsEnabled: Boolean get() = prefs.getBoolean("trusted_apps_enabled", false); set(value) = prefs.edit().putBoolean("trusted_apps_enabled", value).apply()
    var themeMode: ThemeMode get() = runCatching { ThemeMode.valueOf(prefs.getString("theme_mode", ThemeMode.SYSTEM.name)!!) }.getOrDefault(ThemeMode.SYSTEM); set(value) = prefs.edit().putString("theme_mode", value.name).apply()
    var language: AppLanguage get() = runCatching { AppLanguage.valueOf(prefs.getString("language", AppLanguage.SYSTEM.name)!!) }.getOrDefault(AppLanguage.SYSTEM); set(value) = prefs.edit().putString("language", value.name).apply()
    var lowPowerMode: Boolean get() = prefs.getBoolean("low_power_mode", false); set(value) = prefs.edit().putBoolean("low_power_mode", value).apply()
    var pauseUiWhenScreenOff: Boolean get() = prefs.getBoolean("pause_ui_screen_off", true); set(value) = prefs.edit().putBoolean("pause_ui_screen_off", value).apply()
    var uiRefreshSeconds: Int get() = prefs.getInt("ui_refresh_seconds", 2).coerceIn(1, 10); set(value) = prefs.edit().putInt("ui_refresh_seconds", value.coerceIn(1, 10)).apply()
    var historyMaxRecords: Int get() = prefs.getInt("history_max", 500).coerceIn(100, 1000); set(value) = prefs.edit().putInt("history_max", value.coerceIn(100, 1000)).apply()

    // Se muestra una sola vez, la primera vez que el usuario activa el firewall con
    // éxito, para explicar que sin "VPN siempre activa" Android no reinicia Hydra
    // tras un reboot (VpnService.Builder.establish() devuelve null hasta que el
    // usuario reabre la app y reconfirma el permiso de VPN).
    var alwaysOnPromptShown: Boolean get() = prefs.getBoolean("always_on_prompt_shown", false); set(value) = prefs.edit().putBoolean("always_on_prompt_shown", value).apply()
}

/** true si la UI debe mostrarse en inglés (EN, o SISTEMA con el sistema en inglés). */
fun AppLanguage.isEnglish(): Boolean = when (this) {
    AppLanguage.EN -> true
    AppLanguage.ES -> false
    AppLanguage.SYSTEM -> Locale.getDefault().language.equals("en", ignoreCase = true)
}

private fun currentEnglish(context: Context): Boolean = AppSettings(context).language.isEnglish()

fun tr(context: Context, key: String): String {
    val en = currentEnglish(context)
    return when (key) {
        "rules" -> if (en) "RULES" else "REGLAS"
        "connections" -> if (en) "CONNECTIONS" else "CONEXIONES"
        "stats" -> if (en) "STATS" else "ESTADÍSTICAS"
        "profiles" -> if (en) "PROFILES" else "PERFILES"
        "log" -> "LOG"
        "settings" -> if (en) "SETTINGS" else "AJUSTES"
        "help" -> if (en) "HELP" else "AYUDA"
        "about" -> if (en) "ABOUT" else "ACERCA DE"
        "version" -> if (en) "Version" else "Versión"
        "creator" -> if (en) "Developed by WDS657 • Hydraroot" else "Desarrollado por WDS657 • Hydraroot"
        "about_summary" -> if (en) "Hydra Firewall is a no-root Android firewall that uses the local VPN/TUN mechanism to control application traffic without requiring root access." else "Hydra Firewall es un firewall Android sin root que utiliza la VPN/TUN local para controlar el tráfico de las aplicaciones sin requerir acceso root."
        "about_features" -> if (en) "TCP + UDP IPv4 • per-app Wi‑Fi/mobile rules • first-connection prompts • IP blocking • schedules • PIN/biometrics • live traffic status • history and statistics." else "TCP + UDP IPv4 • reglas por app para Wi‑Fi/móvil • avisos en la primera conexión • bloqueo de IP • horarios • PIN/biometría • estado de tráfico en vivo • historial y estadísticas."
        "about_architecture" -> if (en) "Architecture" else "Arquitectura"
        "about_architecture_text" -> if (en) "Hydra Firewall uses Android VpnService/TUN to filter application traffic without root access." else "Hydra Firewall utiliza VpnService/TUN de Android para filtrar el tráfico de las aplicaciones sin acceso root."
        "license" -> if (en) "License" else "Licencia"
        "license_gpl" -> if (en) "GNU General Public License version 3 (GPL-3.0)." else "GNU General Public License versión 3 (GPL-3.0)."
        "view_license" -> if (en) "View GPL v3" else "Ver GPL v3"
        "repository" -> if (en) "Source repository" else "Repositorio del código"
        "open_repository" -> if (en) "Open GitHub repository" else "Abrir repositorio de GitHub"
        "donate" -> if (en) "Buy me a coffee" else "Invitar un café"
        "donate_pending" -> if (en) "Support Hydra Firewall by buying a coffee." else "Podés apoyar Hydra Firewall invitando un café."
        "donate_button" -> if (en) "☕ Invite me a coffee" else "☕ Invitar un café"
        "search_app" -> if (en) "Search application" else "Buscar aplicación"
        "system" -> if (en) "System" else "Sistema"
        "system_app_label" -> if (en) "SYSTEM APPLICATION" else "APLICACIÓN DEL SISTEMA"
        "all" -> if (en) "All" else "Todas"
        "blocked" -> if (en) "Blocked" else "Bloqueadas"
        "history" -> if (en) "History (last 500)" else "Historial (últimas 500)"
        "order" -> if (en) "Sort" else "Orden"
        "csv" -> "CSV"
        "clear" -> if (en) "Clear" else "Limpiar"
        "allow" -> if (en) "ALLOW" else "PERMITIDO"
        "block" -> if (en) "BLOCK" else "BLOQUEADO"
        "permit" -> if (en) "Allow" else "Permitir"
        "deny" -> if (en) "Block" else "Bloquear"
        "blocked_ip" -> if (en) "Blocked IPs" else "IP bloqueadas"
        "add" -> if (en) "Add" else "Añadir"
        "remove" -> if (en) "Remove" else "Quitar"
        "appearance" -> if (en) "Appearance" else "Apariencia"
        "system_apps" -> if (en) "Show system apps" else "Mostrar apps del sistema"
        "maintenance" -> if (en) "Maintenance" else "Mantenimiento"
        "never" -> if (en) "Never" else "Nunca"
        "days7" -> if (en) "7 days" else "7 días"
        "days30" -> if (en) "30 days" else "30 días"
        "clear_all" -> if (en) "Clear history, stats and log" else "Limpiar historial, estadísticas y log"
        "reset_rules" -> if (en) "Reset rules" else "Restablecer reglas"
        "reset_rules_body" -> if (en) "All explicit firewall rules will be removed: per-app rules, port/range rules and blocked IPs. Default firewall settings will be restored." else "Se eliminarán todas las reglas explícitas del firewall: reglas por aplicación, puertos/rangos y las IP bloqueadas. Se restaurará la configuración predeterminada del firewall."
        "reset" -> if (en) "Reset" else "Restablecer"
        "cancel" -> if (en) "Cancel" else "Cancelar"
        "close" -> if (en) "Close" else "Cerrar"
        "default_wifi" -> if (en) "Default Wi-Fi" else "Wi‑Fi predeterminado"
        "default_mobile" -> if (en) "Default mobile data" else "Datos móviles predeterminado"
        "default_rule_info" -> if (en) "Applies to apps without an explicit rule." else "Se aplica a las apps que no tienen una regla explícita."
        "default_prompt_info" -> if (en) "If 'Ask on first connection' is enabled, the prompt appears before this default." else "Si está activo 'Preguntar en la primera conexión', primero aparece el aviso y luego se usa este valor."
        "ask_first" -> if (en) "Ask on first connection" else "Preguntar en la primera conexión"
        "learning_mode_sub" -> if (en) "Analysis only: builds traffic suggestions without changing firewall decisions." else "Solo análisis: genera sugerencias de tráfico sin cambiar las decisiones del firewall."
        "ask_first_sub" -> if (en) "Ask for Wi-Fi/mobile access when an app has no explicit rule." else "Pregunta por Wi‑Fi/móvil para una app sin regla."
        "allow_unknown" -> if (en) "Allow unknown UID" else "Permitir UID desconocido"
        "allow_unknown_sub" -> if (en) "If disabled, UID=INVALID is blocked." else "Si está desactivado, UID=INVALID queda bloqueado."
        "block_ipv6" -> if (en) "Block IPv6" else "Bloquear IPv6"
        "block_ipv6_sub" -> if (en) "Drops all IPv6 traffic; apps fall back to IPv4 (where every filter applies). Use if you see IPv6 leaks." else "Descarta todo el tráfico IPv6; las apps usan IPv4 (donde aplican todos los filtros). Útil si ves fugas por IPv6."
        "advanced_mode" -> if (en) "Advanced mode" else "Modo avanzado"
        "advanced_mode_sub" -> if (en) "Shows extra tabs: IP/Ports, Analyzer, Profiles and Test. Rules you already created stay active even when their tab is hidden." else "Muestra pestañas extra: IP/Puertos, Analizador, Perfiles y Prueba. Las reglas ya creadas siguen activas aunque su pestaña esté oculta."
        "allow_local" -> if (en) "Allow local network" else "Permitir red local"
        "allow_local_sub" -> if (en) "Allows access to private and link-local IPv4 ranges." else "Permite acceso a redes privadas y link-local IPv4."
        "block_roaming" -> if (en) "Block while roaming" else "Bloquear durante roaming"
        "block_roaming_sub" -> if (en) "Blocks mobile traffic while roaming." else "Bloquea tráfico móvil cuando el dispositivo está en roaming."
        "block_screen" -> if (en) "Block with screen off" else "Bloquear con pantalla apagada"
        "block_screen_sub" -> if (en) "Applies a global block while the screen is off." else "Aplica un bloqueo global mientras la pantalla está apagada."
        "blacklist" -> if (en) "Blacklist" else "Lista negra"
        "blacklist_sub" -> if (en) "Only apps with explicit permission are allowed; new apps are blocked unless a rule allows them." else "Solo se permiten las apps con permiso explícito; las nuevas quedan bloqueadas salvo que una regla las permita."
        "whitelist" -> if (en) "Allow by default and block only apps or destinations with explicit deny rules." else "Permitir por defecto y bloquear solo las apps o destinos con reglas de bloqueo explícitas."
        "wifi" -> "Wi‑Fi"
        "mobile" -> if (en) "Mobile" else "Móvil"
        "blocked_by_schedule" -> if (en) "Scheduled block" else "Bloqueo por horario"
        "schedule_short" -> if (en) "Schedule" else "Horario"
        "schedule_short_active" -> if (en) "Schedule ON" else "Horario ON"
        "schedule_sub" -> if (en) "Block this app during selected hours and days." else "Bloquea esta app durante las horas y días seleccionados."
        "from" -> if (en) "From" else "Desde"
        "to" -> if (en) "To" else "Hasta"
        "days" -> if (en) "Days" else "Días"
        "security" -> if (en) "Security" else "Seguridad"
        "lock_app" -> if (en) "Protect app with PIN" else "Proteger app con PIN"
        "lock_sub" -> if (en) "Require authentication when opening the app." else "Pide autenticación al abrir la app."
        "use_fingerprint" -> if (en) "Use fingerprint" else "Usar huella"
        "fingerprint_sub" -> if (en) "Use biometric authentication when available." else "Usa autenticación biométrica cuando esté disponible."
        "change_pin" -> if (en) "Change PIN" else "Cambiar PIN"
        "language" -> if (en) "Language" else "Idioma"
        "system_language" -> if (en) "System" else "Sistema"
        "spanish" -> if (en) "Spanish" else "Español"
        "english" -> "English"
        "secure_dns" -> if (en) "Secure DNS (DNS-over-TLS)" else "DNS seguro (DNS-over-TLS)"
        "ipv6_unavailable" -> if (en) "IPv6 CONNECTION UNAVAILABLE" else "CONEXIÓN IPv6 NO DISPONIBLE"
        "secure_dns_sub" -> if (en) "Intercept IPv4 UDP/53 and forward it through encrypted DNS-over-TLS." else "Intercepta IPv4 UDP/53 y lo envía por DNS-over-TLS cifrado."
        "dns_provider" -> if (en) "DNS-over-TLS provider" else "Proveedor de DNS-over-TLS"
        "dns_provider_default_badge" -> if (en) "DEFAULT" else "PREDETERMINADO"
        "dns_provider_cloudflare_sub" -> if (en) "1.1.1.1 • Recommended, fast and privacy-focused." else "1.1.1.1 • Recomendado, rápido y enfocado en privacidad."
        "dns_provider_google_sub" -> if (en) "8.8.8.8 • Google Public DNS." else "8.8.8.8 • Google Public DNS."
        "dns_provider_quad9_sub" -> if (en) "9.9.9.9 • Blocks known-malicious domains." else "9.9.9.9 • Bloquea dominios maliciosos conocidos."
        "dns_provider_custom" -> if (en) "Custom" else "Personalizado"
        "dns_provider_custom_sub" -> if (en) "Provide your own DNS-over-TLS server." else "Configurá tu propio servidor DNS-over-TLS."
        "dns_custom_ipv4" -> if (en) "IPv4 address(es), comma-separated" else "Dirección(es) IPv4, separadas por coma"
        "dns_custom_ipv6" -> if (en) "IPv6 address(es), comma-separated (optional)" else "Dirección(es) IPv6, separadas por coma (opcional)"
        "dns_custom_hostname" -> if (en) "TLS hostname (SNI / certificate name)" else "Hostname TLS (SNI / nombre del certificado)"
        "dns_custom_incomplete" -> if (en) "Incomplete: falls back to Cloudflare until an IP and hostname are set." else "Incompleto: usa Cloudflare hasta que definas una IP y un hostname."
        "block_ads_title" -> if (en) "Block ads and trackers" else "Bloquear anuncios y rastreadores"
        "block_ads_sub" -> if (en) "Blocks known ad and tracking domains using a local list, before they ever load." else "Bloquea dominios conocidos de anuncios y rastreo con una lista local, antes de que lleguen a cargar."
        "block_ads_list_status" -> if (en) "List: %1\$s · %2\$s domains" else "Lista: %1\$s · %2\$s dominios"
        "block_ads_blocked_today" -> if (en) "Blocked today: %1\$s" else "Bloqueados hoy: %1\$s"
        "block_ads_check_update" -> if (en) "Check for update" else "Buscar actualización"
        "block_ads_checking" -> if (en) "Checking…" else "Buscando…"
        "block_ads_up_to_date" -> if (en) "You're on the latest list." else "Ya tenés la lista más reciente."
        "block_ads_check_failed" -> if (en) "Couldn't check for updates. Check your connection and try again." else "No se pudo buscar actualizaciones. Revisá tu conexión e intentá de nuevo."
        "block_ads_new_available" -> if (en) "A newer list is available (%1\$s)" else "Hay una lista más reciente disponible (%1\$s)"
        "block_ads_update_now" -> if (en) "Update now" else "Actualizar ahora"
        "block_ads_updating" -> if (en) "Downloading and applying…" else "Descargando y aplicando…"
        "block_ads_update_success" -> if (en) "List updated: %1\$s domains" else "Lista actualizada: %1\$s dominios"
        "block_ads_update_failed" -> if (en) "Update failed. The previous list is still active." else "No se pudo actualizar. Sigue activa la lista anterior."
        "block_ads_attribution" -> if (en) "Bundled ad/tracker blocklist built from MIT / CC0-1.0 / CC BY licensed sources only (StevenBlack's ad-hoc list, AdAway, FadeMind hosts.extras, Badd-Boyz-Hosts, hostsVN, minecraft-hosts, Tiuxo, UncheckyAds). Full notice in THIRD_PARTY_NOTICES.md." else "Lista de bloqueo de anuncios/rastreadores empaquetada, armada solo con fuentes con licencia MIT / CC0-1.0 / CC BY (lista ad-hoc de StevenBlack, AdAway, FadeMind hosts.extras, Badd-Boyz-Hosts, hostsVN, minecraft-hosts, Tiuxo, UncheckyAds). Aviso completo en THIRD_PARTY_NOTICES.md."
        "live_traffic" -> if (en) "Live traffic" else "Tráfico en vivo"
        "consumption" -> if (en) "Consumption" else "Consumo"
        "no_data" -> if (en) "No traffic recorded yet" else "Sin consumo registrado todavía"
        "schedule_all_day" -> if (en) "Same start/end = all selected day" else "Misma hora de inicio/fin = todo el día seleccionado"
        "sort_time" -> if (en) "Time" else "Hora"
        "sort_app" -> if (en) "Application" else "Aplicación"
        "sort_ip" -> "IP"
        "sort_port" -> if (en) "Port" else "Puerto"
        "allow_ip" -> if (en) "Allow IP" else "Permitir IP"
        "block_ip" -> if (en) "Block IP" else "Bloquear IP"
        "ip_blocked" -> if (en) "IP blocked" else "IP bloqueada"
        "domain_unavailable" -> if (en) "unavailable" else "no disponible"
        "connections_word" -> if (en) "Connections" else "Conexiones"
        "blocked_word" -> if (en) "Blocked" else "Bloqueadas"
        "save" -> if (en) "Save" else "Guardar"
        "allow_temp_10" -> if (en) "Allow 10 min" else "Permitir 10 min"
        "allow_temp_60" -> if (en) "Allow 1 h" else "Permitir 1 h"
        "allow_always" -> if (en) "Allow always" else "Permitir siempre"
        "block_temp_10" -> if (en) "Block 10 min" else "Bloquear 10 min"
        "block_temp_60" -> if (en) "Block 1 h" else "Bloquear 1 h"
        "block_always" -> if (en) "Block always" else "Bloquear siempre"
        else -> key
    }
}
