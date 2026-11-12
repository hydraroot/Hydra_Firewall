package com.hydra.firewall

/**
 * Plain-language explanations for the exact policy branch recorded with a connection.
 * This deliberately does not inspect current settings: historical decisions must not be
 * re-explained using rules that may have changed since the event was recorded.
 */
object ConnectionDecisionText {
    fun explanation(reasonCode: String?, blocked: Boolean, english: Boolean): String {
        val code = reasonCode?.takeIf { it.isNotBlank() } ?: "UNCLASSIFIED"
        return when (code) {
            "GLOBAL_BLOCK_ALL" -> if (english) {
                "The global Block All switch was enabled when Hydra evaluated this connection."
            } else {
                "El interruptor global Bloquear todo estaba activado cuando Hydra evaluó esta conexión."
            }
            "INVALID_UID_POLICY" -> if (english) {
                "Android could not identify the app that owned this traffic. Hydra applied the configured unknown-app policy."
            } else {
                "Android no pudo identificar qué aplicación originó este tráfico. Hydra aplicó la política configurada para aplicaciones desconocidas."
            }
            "POLICY_PRECHECK" -> if (english) {
                "A mandatory firewall pre-check made this decision. The record does not contain a more specific cause."
            } else {
                "Una comprobación obligatoria del firewall tomó esta decisión. El registro no conserva una causa más específica."
            }
            "SCHEDULE" -> if (english) {
                "The app's scheduled blocking period was active when this connection was evaluated."
            } else {
                "El horario de bloqueo de esta aplicación estaba activo cuando se evaluó la conexión."
            }
            "USER_IP_BLOCK" -> if (english) {
                "The destination IP matched an address or range in your IP block rules."
            } else {
                "La IP de destino coincidió con una dirección o rango de tus reglas de bloqueo de IP."
            }
            "THREAT_IP", "QUIC_THREAT_IP" -> if (english) {
                "The destination IP matched an indicator in the threat-intelligence database."
            } else {
                "La IP de destino coincidió con un indicador de la base de inteligencia de amenazas."
            }
            "THREAT_DOMAIN", "QUIC_THREAT_DOMAIN" -> if (english) {
                "The requested domain matched an indicator in the threat-intelligence database."
            } else {
                "El dominio solicitado coincidió con un indicador de la base de inteligencia de amenazas."
            }
            "AD_TRACKER_BLOCKLIST", "QUIC_BLOCKLIST_DOMAIN" -> if (english) {
                "The domain matched the enabled advertising and tracker blocklist."
            } else {
                "El dominio coincidió con la lista activa de publicidad y rastreadores."
            }
            "CUSTOM_DOMAIN_BLOCK", "QUIC_CUSTOM_DOMAIN" -> if (english) {
                "A custom domain rule explicitly blocks this domain."
            } else {
                "Una regla personalizada de dominios bloquea explícitamente este dominio."
            }
            "LOCAL_NETWORK_POLICY" -> if (english) {
                "This app's local-network setting blocks access to the private or local destination."
            } else {
                "El ajuste de red local de esta aplicación bloquea el acceso al destino privado o local."
            }
            "SCREEN_OFF" -> if (english) {
                "The firewall is configured to block this app while the device screen is off."
            } else {
                "El firewall está configurado para bloquear esta aplicación cuando la pantalla del dispositivo está apagada."
            }
            "ROAMING" -> if (english) {
                "The app's roaming setting blocks mobile traffic while the device is roaming."
            } else {
                "El ajuste de roaming de esta aplicación bloquea los datos móviles mientras el dispositivo está en roaming."
            }
            "TEMPORARY_APP_RULE" -> if (english) {
                if (blocked) "The temporary app permission did not allow this network." else "The temporary app permission allowed this network."
            } else {
                if (blocked) "El permiso temporal de la aplicación no permitía esta red." else "El permiso temporal de la aplicación permitía esta red."
            }
            "ADVANCED_PORT_RULE" -> if (english) {
                if (blocked) "A matching advanced protocol/port rule blocked this connection." else "A matching advanced protocol/port rule allowed this connection."
            } else {
                if (blocked) "Una regla avanzada coincidente de protocolo y puerto bloqueó esta conexión." else "Una regla avanzada coincidente de protocolo y puerto permitió esta conexión."
            }
            "USER_ESSENTIAL_DEFAULT" -> if (english) {
                "The app was allowed by the default policy for apps marked as Essential."
            } else {
                "La aplicación fue permitida por la política predeterminada para aplicaciones marcadas como Esenciales."
            }
            "NON_APPLICATION_UID" -> if (english) {
                "Android reported a UID that does not belong to a regular app; Hydra's policy blocks this traffic."
            } else {
                "Android informó un UID que no corresponde a una aplicación normal; la política de Hydra bloquea este tráfico."
            }
            "EXPLICIT_APP_RULE" -> if (english) {
                if (blocked) "The saved Wi-Fi/mobile rule for this app blocks the network used by this connection." else "The saved Wi-Fi/mobile rule for this app allows the network used by this connection."
            } else {
                if (blocked) "La regla guardada de Wi-Fi/datos de esta aplicación bloquea la red usada por esta conexión." else "La regla guardada de Wi-Fi/datos de esta aplicación permite la red usada por esta conexión."
            }
            "DEFAULT_APP_RULE" -> if (english) {
                if (blocked) "The default Wi-Fi/mobile policy for apps without their own rule blocks this network." else "The default Wi-Fi/mobile policy for apps without their own rule allows this network."
            } else {
                if (blocked) "La política predeterminada de Wi-Fi/datos para aplicaciones sin regla propia bloquea esta red." else "La política predeterminada de Wi-Fi/datos para aplicaciones sin regla propia permite esta red."
            }
            "NO_ACTIVE_NETWORK" -> if (english) {
                "Hydra had no active network type to which this app permission could apply."
            } else {
                "Hydra no tenía un tipo de red activo al que pudiera aplicarse el permiso de esta aplicación."
            }
            "USER_CONNECTION_EXCEPTION" -> if (english) {
                "A user-created exception allowed only this UID to reach this exact IP, protocol and port. Confirmed threat matches and global Block All still take priority."
            } else {
                "Una excepción creada por el usuario permitió que este UID llegara únicamente a esta IP, protocolo y puerto. Las amenazas confirmadas y Bloquear todo siguen teniendo prioridad."
            }
            "USER_DOMAIN_EXCEPTION" -> if (english) {
                "A user-created domain exception allowed this domain for this UID. Confirmed threat signatures still take priority."
            } else {
                "Una excepción creada por el usuario permitió este dominio para este UID. Las firmas de amenazas confirmadas siguen teniendo prioridad."
            }
            "USER_IP_EXCEPTION" -> if (english) {
                "A per-app exception for this destination IP allowed the connection."
            } else {
                "Una excepción de IP configurada para esta aplicación permitió la conexión."
            }
            "SYSTEM_DNS_DEFAULT" -> if (english) {
                "This is Android's system DNS resolver traffic. Hydra allows it so apps can resolve names; domain filtering is evaluated separately."
            } else {
                "Es tráfico del resolvedor DNS del sistema Android. Hydra lo permite para que las aplicaciones resuelvan nombres; el filtrado de dominios se evalúa por separado."
            }
            "QUIC_POLICY_BLOCK" -> if (english) {
                "The QUIC protection policy rejected this datagram."
            } else {
                "La política de protección QUIC rechazó este datagrama."
            }
            "FIRST_CONNECTION_PROMPT" -> if (english) {
                "The app had no saved decision. Hydra held this attempt while asking you whether to allow or block the app."
            } else {
                "La aplicación todavía no tenía una decisión guardada. Hydra detuvo este intento mientras te preguntaba si querías permitirla o bloquearla."
            }
            "ALLOWED_BY_POLICY" -> if (english) {
                "The connection passed Hydra's firewall policy when it was recorded."
            } else {
                "La conexión superó la política del firewall de Hydra cuando se registró."
            }
            "UNCLASSIFIED", "UNCLASSIFIED_BLOCK" -> if (english) {
                if (blocked) "This record does not contain the exact rule that blocked the connection. New records store the cause at decision time." else "This record says the connection was allowed, but the exact allow rule was not stored."
            } else {
                if (blocked) "Este registro no conserva la regla exacta que bloqueó la conexión. Los registros nuevos guardan la causa al tomar la decisión." else "Este registro indica que la conexión fue permitida, pero no conserva la regla exacta que la permitió."
            }
            else -> if (english) {
                if (blocked) "The connection was blocked, but this record does not contain a recognized reason code." else "The connection was allowed, but this record does not contain a recognized reason code."
            } else {
                if (blocked) "La conexión fue bloqueada, pero este registro no contiene un código de motivo reconocido." else "La conexión fue permitida, pero este registro no contiene un código de motivo reconocido."
            }
        }
    }
}
