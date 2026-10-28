package com.hydra.firewall.vpn

/**
 * Punto 4 — "¿Por qué se conecta?". Lógica PURA (sin Android) que convierte hechos ya conocidos sobre una
 * conexión en frases cortas y honestas, en español e inglés.
 *
 * Principios:
 *  - Solo afirma lo que se sabe. Si no hay dominio, no lo inventa: lo dice.
 *  - No emite veredictos ("es malware"): describe señales y su nivel (INFO / AVISO / ALERTA / PELIGRO).
 *  - Las señales débiles (puerto raro, app instalada fuera de Play) nunca pasan de AVISO.
 */
object ConnectionExplainer {

    enum class Level { INFO, NOTICE, WARNING, DANGER }

    data class Reason(val level: Level, val es: String, val en: String) {
        fun text(english: Boolean): String = if (english) en else es
    }

    enum class InstallSource { PLAY_STORE, SYSTEM, OTHER_STORE, SIDELOADED, UNKNOWN }

    data class Facts(
        /** IP o host tal como lo ve el firewall (sin puerto). Puede ser null si no se conoce. */
        val destinationHost: String?,
        /** Nombre de dominio que la app resolvió o que se obtuvo por DNS inverso; null si no se sabe. */
        val domain: String?,
        val port: Int,
        val protocol: String,
        /** true/false si ya se decidió (historial); null si todavía se está decidiendo (aviso de primera conexión). */
        val allowed: Boolean? = null,
        val firstConnection: Boolean = false,
        val domainOnBlocklist: Boolean = false,
        /** Descripción de la coincidencia de inteligencia de amenazas, o null. */
        val threatDetail: String? = null,
        val installSource: InstallSource = InstallSource.UNKNOWN,
        val installedDaysAgo: Long? = null,
        val updatedDaysAgo: Long? = null,
        val repeatCount: Int = 1
    )

    data class Endpoint(val host: String, val port: Int)

    /** "1.2.3.4:443" | "[2001:db8::1]:443" | "host:80" -> Endpoint. Sin puerto válido devuelve null. */
    fun parseEndpoint(raw: String): Endpoint? {
        val s = raw.trim()
        if (s.isEmpty()) return null
        if (s.startsWith("[")) {
            val end = s.indexOf(']')
            if (end < 2) return null
            val port = s.substring(end + 1).removePrefix(":").toIntOrNull() ?: return null
            return if (port in 0..65535) Endpoint(s.substring(1, end), port) else null
        }
        val colon = s.lastIndexOf(':')
        if (colon <= 0) return null
        // Más de un ':' sin corchetes sería una IPv6 sin puerto: no es un endpoint.
        if (s.indexOf(':') != colon) return null
        val port = s.substring(colon + 1).toIntOrNull() ?: return null
        return if (port in 0..65535) Endpoint(s.substring(0, colon), port) else null
    }

    private val IPV4 = Regex("^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$")
    private val IPV6_CHARS = Regex("^[0-9A-Fa-f:.]+$")

    /** Literal IPv4/IPv6 (no hace ninguna consulta de red). */
    fun isIpLiteral(host: String): Boolean {
        val h = host.trim().trim('[', ']').substringBefore('%') // %wlan0 = zona de enlace local
        return IPV4.matches(h) || (h.contains(':') && IPV6_CHARS.matches(h))
    }

    /** Servicio habitual de un puerto: (español, inglés). null si no es un puerto conocido. */
    fun portService(port: Int): Pair<String, String>? = when (port) {
        443 -> "HTTPS (web o API cifrada)" to "HTTPS (encrypted web or API)"
        80 -> "HTTP (web sin cifrar)" to "HTTP (unencrypted web)"
        53 -> "DNS (resolución de nombres)" to "DNS (name resolution)"
        853 -> "DNS sobre TLS" to "DNS over TLS"
        123 -> "NTP (hora de red)" to "NTP (network time)"
        5228, 5229, 5230 -> "Google Play Services / notificaciones push" to "Google Play Services / push notifications"
        25, 465, 587 -> "correo saliente (SMTP)" to "outgoing mail (SMTP)"
        110, 995 -> "correo entrante (POP3)" to "incoming mail (POP3)"
        143, 993 -> "correo entrante (IMAP)" to "incoming mail (IMAP)"
        8080, 8443 -> "web en puerto alternativo" to "web on an alternate port"
        3478, 5349 -> "llamadas/videollamadas (STUN/TURN)" to "calls/video calls (STUN/TURN)"
        1883, 8883 -> "mensajería MQTT (IoT)" to "MQTT messaging (IoT)"
        else -> null
    }

    /** Puertos que merecen atención: (nivel, español, inglés). Redactados sin afirmar que sea malicioso. */
    private fun riskyPort(port: Int): Triple<Level, String, String>? = when (port) {
        23 -> Triple(Level.WARNING, "Puerto 23 (Telnet): protocolo antiguo y sin cifrar; hoy casi ninguna app legítima lo usa.", "Port 23 (Telnet): old, unencrypted protocol; almost no legitimate app uses it today.")
        5555 -> Triple(Level.WARNING, "Puerto 5555 (ADB): es el de depuración remota de Android; no es normal en una app común.", "Port 5555 (ADB): Android remote debugging; not normal for a regular app.")
        4444, 6667 -> Triple(Level.NOTICE, "Puerto $port: lo usan herramientas de acceso remoto y algunos botnets, aunque también software legítimo.", "Port $port: used by remote-access tools and some botnets, though also by legitimate software.")
        3389 -> Triple(Level.NOTICE, "Puerto 3389 (Escritorio remoto): poco habitual para una app de celular.", "Port 3389 (Remote Desktop): unusual for a phone app.")
        445, 139 -> Triple(Level.NOTICE, "Puerto $port (archivos compartidos de Windows/SMB): inusual fuera de la red local.", "Port $port (Windows file sharing/SMB): unusual outside the local network.")
        else -> null
    }

    private fun levelRank(l: Level) = when (l) { Level.DANGER -> 3; Level.WARNING -> 2; Level.NOTICE -> 1; Level.INFO -> 0 }

    fun explain(f: Facts, max: Int = 6): List<Reason> {
        val out = mutableListOf<Reason>()
        fun add(level: Level, es: String, en: String) { out += Reason(level, es, en) }

        f.threatDetail?.takeIf { it.isNotBlank() }?.let {
            add(Level.DANGER, "Coincide con inteligencia de amenazas: $it.", "Matches threat intelligence: $it.")
        }

        val domain = f.domain?.trim()?.takeIf { it.isNotEmpty() }
        val host = f.destinationHost?.trim()?.trim('[', ']')?.takeIf { it.isNotEmpty() }
        if (domain != null) {
            if (f.domainOnBlocklist) {
                add(Level.WARNING, "El dominio $domain figura en las listas de anuncios, rastreo o malware.", "The domain $domain is on the ad, tracking or malware lists.")
            } else {
                add(Level.INFO, "Se conecta a $domain.", "Connecting to $domain.")
            }
        } else if (host != null && isIpLiteral(host)) {
            add(
                Level.NOTICE,
                "Conexión directa a la IP $host sin un nombre de dominio conocido. Puede ser normal (servidores con IP fija, DNS propio de la app), pero nada lo confirma.",
                "Direct connection to IP $host with no known domain name. It can be normal (fixed-IP servers, the app's own DNS), but nothing confirms it."
            )
        }

        riskyPort(f.port)?.let { add(it.first, it.second, it.third) } ?: portService(f.port)?.let { (es, en) ->
            if (f.port == 443 && domain != null) Unit // ya dicho arriba; evita repetir lo obvio
            else add(Level.INFO, "Puerto ${f.port}: $es.", "Port ${f.port}: $en.")
        }
        if (f.port == 80) add(Level.NOTICE, "Sin cifrado: lo que se envíe por HTTP podría verse en tránsito.", "No encryption: anything sent over HTTP could be seen in transit.")

        if (f.firstConnection) {
            add(Level.INFO, "Es la primera vez que esta app intenta salir a internet por esta red.", "This is the first time this app tries to reach the internet on this network.")
        }

        when (f.installSource) {
            InstallSource.PLAY_STORE -> add(Level.INFO, "Instalada desde Google Play.", "Installed from Google Play.")
            InstallSource.SYSTEM -> add(Level.INFO, "Es una app del sistema.", "This is a system app.")
            InstallSource.OTHER_STORE -> add(Level.INFO, "Instalada desde otra tienda de apps.", "Installed from another app store.")
            InstallSource.SIDELOADED -> add(Level.NOTICE, "Instalada fuera de una tienda (APK externa): no pasó por ninguna revisión de tienda.", "Installed outside a store (external APK): it did not go through any store review.")
            InstallSource.UNKNOWN -> Unit
        }

        val installed = f.installedDaysAgo
        val updated = f.updatedDaysAgo
        if (installed != null && installed < 1) {
            add(Level.NOTICE, "Se instaló hace menos de 24 horas.", "Installed less than 24 hours ago.")
        } else if (updated != null && updated < 3 && (installed == null || installed >= 3)) {
            add(Level.INFO, "Se actualizó hace $updated ${if (updated == 1L) "día" else "días"}; una actualización puede sumar destinos nuevos.", "Updated $updated ${if (updated == 1L) "day" else "days"} ago; an update can add new destinations.")
        }

        if (f.allowed == false && f.repeatCount >= 20) {
            add(Level.NOTICE, "Insistió ${f.repeatCount} veces: la app reintenta; si la bloqueás podría dejar de funcionar.", "It tried ${f.repeatCount} times: the app keeps retrying; blocking it may break it.")
        }

        // Mayor gravedad primero; a igual gravedad, se conserva el orden de arriba. Siempre cabe la de mayor nivel.
        return out.withIndex()
            .sortedWith(compareByDescending<IndexedValue<Reason>> { levelRank(it.value.level) }.thenBy { it.index })
            .map { it.value }
            .take(max.coerceAtLeast(1))
    }

    fun highestLevel(reasons: List<Reason>): Level =
        reasons.maxByOrNull { levelRank(it.level) }?.level ?: Level.INFO
}
