package com.hydra.firewall.security

/**
 * Punto 6 — Estado del pack de amenazas en lenguaje claro. Lógica PURA (el reloj entra como parámetro).
 */
object ThreatPackStatusFormat {

    enum class Health { OK, EXPIRING_SOON, EXPIRED, BUNDLED_ONLY, DISABLED }

    const val EXPIRING_SOON_DAYS = 3L
    private const val DAY_MS = 24L * 60L * 60L * 1000L

    data class Summary(
        val health: Health,
        val headlineEs: String,
        val headlineEn: String,
        val indicatorCount: Int,
        val ageDays: Long?,
        val daysToExpire: Long?
    ) {
        fun headline(english: Boolean) = if (english) headlineEn else headlineEs
    }

    /** Un pack incluido en la app (no descargado) no tiene fuentes de red: lo reconocemos por no tener `lastUpdateMs`. */
    fun summarize(
        status: ThreatSignatureStatus,
        feedConfigured: Boolean,
        lastUpdateMs: Long,
        nowMs: Long
    ): Summary {
        val indicators = status.sha256Count + status.domainCount + status.ipCount + status.urlCount
        val age = if (status.generatedAt > 0) ((nowMs - status.generatedAt) / DAY_MS).coerceAtLeast(0L) else null
        val toExpire = if (status.expiresAt > 0) {
            val ms = status.expiresAt - nowMs
            if (ms >= 0) ms / DAY_MS else -((-ms + DAY_MS - 1) / DAY_MS)
        } else null

        if (!status.enabled) {
            return Summary(Health.DISABLED, "Firmas de amenazas desactivadas.", "Threat signatures are turned off.", indicators, age, toExpire)
        }
        if (status.expiresAt > 0 && status.expiresAt < nowMs) {
            return Summary(Health.EXPIRED, "El pack venció: se ignora y se usa el incluido en la app.", "The pack expired: it is ignored and the one bundled in the app is used.", indicators, age, toExpire)
        }
        if (toExpire != null && toExpire <= EXPIRING_SOON_DAYS) {
            return Summary(Health.EXPIRING_SOON, "El pack vence pronto (en ${maxOf(toExpire, 0)} d).", "The pack expires soon (in ${maxOf(toExpire, 0)} d).", indicators, age, toExpire)
        }
        if (lastUpdateMs <= 0L) {
            val tail = if (feedConfigured) "todavía no se descargó ninguna actualización." else "la actualización automática no está configurada."
            val tailEn = if (feedConfigured) "no update has been downloaded yet." else "automatic updates are not configured."
            return Summary(Health.BUNDLED_ONLY, "Se usa el pack incluido en la app; $tail", "Using the pack bundled in the app; $tailEn", indicators, age, toExpire)
        }
        return Summary(Health.OK, "Pack al día.", "Pack up to date.", indicators, age, toExpire)
    }

    fun updateModeText(feedConfigured: Boolean, feedHost: String?, english: Boolean): String = when {
        !feedConfigured -> if (english) "Automatic updates: off (no feed URL configured)" else "Actualización automática: desactivada (no hay URL de feed)"
        else -> if (english) "Automatic updates: daily from ${feedHost ?: "configured feed"}" else "Actualización automática: diaria desde ${feedHost ?: "el feed configurado"}"
    }

    /** Solo el host: no mostramos ni guardamos rutas/consultas de la URL en pantalla. */
    fun hostOf(url: String): String? = runCatching {
        val u = url.trim()
        if (!u.startsWith("https://", ignoreCase = true)) return@runCatching null
        u.substring(8).substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@').substringBefore(':').takeIf { it.isNotBlank() }
    }.getOrNull()

    /** Traduce los códigos internos de error a algo entendible (los textos crudos quedan para el log). */
    fun friendlyError(code: String?, english: Boolean): String? {
        val c = code?.trim().orEmpty()
        if (c.isEmpty()) return null
        return when {
            c == "signature_invalid" -> if (english) "The downloaded pack has an invalid signature and was rejected." else "El pack descargado tiene una firma inválida y fue rechazado."
            c == "feed_requires_https" -> if (english) "The feed URL must start with https://." else "La URL del feed debe empezar con https://."
            c == "pack_too_large" -> if (english) "The pack is too large." else "El pack es demasiado grande."
            c == "pack_install_failed" -> if (english) "The pack could not be installed (expired, too large or older than the current one)." else "No se pudo instalar el pack (vencido, demasiado grande o más viejo que el actual)."
            c == "feed_downgraded_to_http" -> if (english) "The feed redirected to an insecure address and was rejected." else "El feed redirigió a una dirección insegura y fue rechazado."
            c.startsWith("http_") -> if (english) "The server answered with error ${c.removePrefix("http_")}." else "El servidor respondió con error ${c.removePrefix("http_")}."
            else -> if (english) "Update failed ($c)." else "Falló la actualización ($c)."
        }
    }
}
