package com.hydra.firewall.vpn

import java.util.concurrent.ConcurrentHashMap

/**
 * V1.1 - Alcance reducido a propósito: NO es la tabla de sesiones TCP con
 * estado que usará el motor futuro (esa incluirá máquina de estados, ventanas,
 * secuencias). Acá solo sirve para:
 *
 *   1. Saber si una tupla ya fue vista, para no volver a resolver UID
 *      UID solo en el SYN, no en cada segmento).
 *   2. Deduplicar el log.
 *
 * La forma del SessionKey (5-tupla) es la misma que usa el motor TCP, para no
 * tener que romper esta interfaz cuando se agregue la máquina de estados.
 */
class SessionTable {

    data class Entry(val firstSeenMs: Long, var lastSeenMs: Long)

    private val sessions = ConcurrentHashMap<SessionKey, Entry>()

    companion object {
        // por estado TCP real, que no existe en esta versión). Alcanza con un
        // valor simple para no acumular memoria en una sesión de prueba larga.
        const val ENTRY_TTL_MS = 60_000L
    }

    /** true si es la primera vez que se ve esta tupla (o ya expiró). */
    fun isFirstSeen(key: SessionKey): Boolean {
        val now = System.currentTimeMillis()
        val existing = sessions[key]

        if (existing == null || (now - existing.lastSeenMs) > ENTRY_TTL_MS) {
            sessions[key] = Entry(firstSeenMs = now, lastSeenMs = now)
            return true
        }

        existing.lastSeenMs = now
        return false
    }

    fun remove(key: SessionKey) {
        sessions.remove(key)
    }

    fun purgeExpired() {
        val now = System.currentTimeMillis()
        val iterator = sessions.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastSeenMs > ENTRY_TTL_MS) {
                iterator.remove()
            }
        }
    }

    fun clear() {
        sessions.clear()
    }

    fun activeCount(): Int = sessions.size
}
