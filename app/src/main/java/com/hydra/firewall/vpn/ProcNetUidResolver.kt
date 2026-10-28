package com.hydra.firewall.vpn

import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Fallback de resolución de UID para API 24-28 (Android 7.0 - 9.0 Pie).
 *
 * Reescrito para reproducir el algoritmo de get_uid()/get_uid_sub()
 * sin aproximaciones en la tupla de socket. Además corrige la posición real de
 * la columna UID en /proc/net. Al partir cada fila de datos por espacios, "sl" queda
 * como "0:" (columna 0) y tx_queue:rx_queue / tr:tm->when vienen pegados con ":", asi
 * que el UID es la columna 7 (la 8 es "timeout", casi siempre 0).
 * Diferencias corregidas respecto
 * a la versión anterior de este archivo, encontradas comparando código contra
 * código:
 *
 *      crudos, en el mismo orden en que aparecen en el archivo) y LUEGO aplica
 *      htonl() a esos bytes interpretados como palabras de 32 bits, para
 *      llevarlos a network byte order - el mismo orden en que ya vienen los
 *      parámetros saddr/daddr (tomados directo del paquete IP). Acá se hace
 *      el equivalente: se decodifica el hex de la línea, se interpreta cada
 *      bloque de 4 bytes como si fuera big-endian tras "voltear" el resultado
 *      de la lectura little-endian del kernel - ver decodeKernelHexAddress().
 *
 *   2. get_uid() prueba PRIMERO la tabla IPv6 (tcp6/udp6), mapeando la IPv4 a
 *      formato IPv4-mapped-IPv6 (::ffff:a.b.c.d = 10 bytes en 0x00 + 0xFFFF +
 *      los 4 bytes de la IPv4). Solo si esa búsqueda no encuentra nada
 *      (uid == -1), cae al fallback de buscar en la tabla IPv4 nativa. Esto
 *      importa porque en Android, muchos sockets "IPv4" en realidad se crean
 *      como sockets IPv6 dual-stack y solo aparecen en la tabla v6.
 *
 *   3. Wildcards: una entrada de la tabla /proc con dirección 0.0.0.0 (todo
 *      ceros) o puerto de destino 0 hace match contra cualquier IP/puerto de
 *      la tupla buscada (típico de sockets en estado LISTEN). La versión
 *      anterior de este archivo exigía coincidencia exacta siempre.
 *
 * Regla no negociable: si no hay coincidencia real en /proc/net, se devuelve
 * null. Como segunda comprobacion se acepta un unico UID para el endpoint local
 * exacto (IP + puerto + protocolo), que sigue siendo evidencia directa de la
 * tabla de sockets y evita falsos INVALID_UID cuando el remoto cambia/late.
 * Si hay mas de un UID para ese endpoint local, el resultado es ambiguo y se
 * devuelve null.
 */
object ProcNetUidResolver {

    private const val TAG = "ProcNetUidResolver"

    private const val PATH_TCP = "/proc/net/tcp"
    private const val PATH_TCP6 = "/proc/net/tcp6"
    private const val PATH_UDP = "/proc/net/udp"
    private const val PATH_UDP6 = "/proc/net/udp6"

    /**
     * Fila de datos de /proc/net/{tcp,udp}[6] partida por espacios:
     * 0="N:", 1=local, 2=remote, 3=st, 4="tx:rx", 5="tr:tm", 6=retrnsmt, 7=uid, 8=timeout, 9=inode.
     */
    private const val UID_COLUMN = 7

    /**
     * Punto de entrada, equivalente a get_uid() en ip.c: para tráfico IPv4,
     * intenta primero la tabla IPv6 (con la IPv4 mapeada), y si no encuentra
     * nada cae a la tabla IPv4 nativa. Para tráfico ya IPv6, va directo a
     * la tabla v6.
     */
    fun resolve(key: SessionKey): Int? {
        val isIpv4 = key.srcAddr is Inet4Address

        if (isIpv4) {
            val mappedResult = resolveSub(
                protocol = key.protocol,
                srcAddr = toIpv4MappedIpv6(key.srcAddr),
                srcPort = key.srcPort,
                dstAddr = toIpv4MappedIpv6(key.dstAddr),
                dstPort = key.dstPort,
                path = pathFor(key.protocol, isIpv6 = true)
            )
            if (mappedResult != null) return mappedResult

            // Fallback: tabla IPv4 nativa, igual que "if (uid == -1)" en get_uid().
            return resolveSub(
                protocol = key.protocol,
                srcAddr = key.srcAddr,
                srcPort = key.srcPort,
                dstAddr = key.dstAddr,
                dstPort = key.dstPort,
                path = pathFor(key.protocol, isIpv6 = false)
            )
        } else {
            return resolveSub(
                protocol = key.protocol,
                srcAddr = key.srcAddr,
                srcPort = key.srcPort,
                dstAddr = key.dstAddr,
                dstPort = key.dstPort,
                path = pathFor(key.protocol, isIpv6 = true)
            )
        }
    }

    /**
     * Test-only hook: runs the real column-parsing code (resolveSub) against
     * a caller-supplied file instead of the live /proc/net path, so a self-
     * check can verify the UID column fix (FIX117) without root or a device
     * with an actual matching socket.
     */
    internal fun debugReadUidFromFile(
        file: File,
        srcAddrHexUnused: String,
        srcPortHexUnused: String,
        dstAddrHexUnused: String,
        dstPortHexUnused: String
    ): Int? {
        // The caller passes the same kernel-hex fields written into the fixture
        // row so the intent at the call site is self-documenting; decode them
        // with the same routine the real parser uses instead of hand-rolling
        // IPv4 dotted parsing here.
        val srcAddr = decodeKernelHexAddress(srcAddrHexUnused) ?: return null
        val dstAddr = decodeKernelHexAddress(dstAddrHexUnused) ?: return null
        val srcPort = srcPortHexUnused.toIntOrNull(16) ?: return null
        val dstPort = dstPortHexUnused.toIntOrNull(16) ?: return null
        return resolveSub(UidResolver.PROTOCOL_TCP, srcAddr, srcPort, dstAddr, dstPort, file.path)
    }

    private fun pathFor(protocol: Int, isIpv6: Boolean): String? = when {
        protocol == UidResolver.PROTOCOL_TCP && !isIpv6 -> PATH_TCP
        protocol == UidResolver.PROTOCOL_TCP && isIpv6 -> PATH_TCP6
        protocol == UidResolver.PROTOCOL_UDP && !isIpv6 -> PATH_UDP
        protocol == UidResolver.PROTOCOL_UDP && isIpv6 -> PATH_UDP6
        else -> null
    }

    /** IPv4-mapped-IPv6: 10 bytes en 0x00, luego 0xFF 0xFF, luego los 4 bytes de la IPv4. */
    private fun toIpv4MappedIpv6(addr: InetAddress): ByteArray {
        val v4 = addr.address // 4 bytes, network byte order
        val mapped = ByteArray(16)
        mapped[10] = 0xFF.toByte()
        mapped[11] = 0xFF.toByte()
        v4.copyInto(mapped, destinationOffset = 12)
        return mapped
    }

    private fun toIpv4MappedIpv6(addr: ByteArray): ByteArray {
        val mapped = ByteArray(16)
        mapped[10] = 0xFF.toByte()
        mapped[11] = 0xFF.toByte()
        addr.copyInto(mapped, destinationOffset = 12)
        return mapped
    }

    // Sobrecarga usada cuando srcAddr ya es InetAddress (caso normal).
    private fun resolveSub(
        protocol: Int,
        srcAddr: ByteArray,
        srcPort: Int,
        dstAddr: ByteArray,
        dstPort: Int,
        path: String?
    ): Int? {
        if (path == null) return null

        val file = File(path)
        if (!file.exists() || !file.canRead()) {
            Log.w(TAG, "$path no existe o no es legible")
            return null
        }

        val addrWidthBytes = srcAddr.size // 4 (IPv4) o 16 (IPv6, incluye IPv4-mapped)
        val zero = ByteArray(addrWidthBytes)

        var uid: Int? = null
        var localEndpointUid: Int? = null
        var localEndpointAmbiguous = false

        try {
            BufferedReader(FileReader(file)).use { reader ->
                reader.readLine() // encabezado, descartado igual que "if (!l++) continue;" en ip.c

                var line = reader.readLine()
                while (line != null) {
                    val columns = line.trim().split(Regex("\\s+"))
                    // columns[1]=local_address, columns[2]=rem_address, columns[7]=uid
                    if (columns.size > UID_COLUMN) {
                        val localPart = columns[1].split(":")
                        val remotePart = columns[2].split(":")

                        if (localPart.size == 2 && remotePart.size == 2) {
                            val lineSrcAddr = decodeKernelHexAddress(localPart[0])
                            val lineSrcPort = localPart[1].toIntOrNull(16)
                            val lineDstAddr = decodeKernelHexAddress(remotePart[0])
                            val lineDstPort = remotePart[1].toIntOrNull(16)
                            val candidateUid = columns[UID_COLUMN].toIntOrNull()

                            if (lineSrcAddr != null && lineSrcPort != null &&
                                lineDstAddr != null && lineDstPort != null &&
                                lineSrcAddr.size == addrWidthBytes && lineDstAddr.size == addrWidthBytes
                            ) {
                                // First preference: exact 5-tuple / wildcard-remote match.
                                val srcMatches = lineSrcAddr.contentEquals(srcAddr) ||
                                        lineSrcAddr.contentEquals(zero)
                                val dstMatches = lineDstAddr.contentEquals(dstAddr) ||
                                        lineDstAddr.contentEquals(zero)
                                val srcPortMatches = lineSrcPort == srcPort
                                val dstPortMatches = lineDstPort == dstPort || lineDstPort == 0

                                if (candidateUid != null && srcPortMatches && dstPortMatches && srcMatches && dstMatches) {
                                    uid = candidateUid
                                }

                                // Second preference: unique exact LOCAL endpoint match.
                                // This is still direct socket-table evidence and is
                                // especially useful for Android 7 when the remote
                                // tuple is not yet visible or differs during startup.
                                val exactLocal = candidateUid != null &&
                                        lineSrcPort == srcPort &&
                                        lineSrcAddr.contentEquals(srcAddr)
                                if (exactLocal && !localEndpointAmbiguous) {
                                    if (localEndpointUid == null) {
                                        localEndpointUid = candidateUid
                                    } else if (localEndpointUid != candidateUid) {
                                        localEndpointAmbiguous = true
                                        localEndpointUid = null
                                    }
                                }
                            }
                        }
                    }
                    line = reader.readLine()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error leyendo $path", e)
            return null
        }

        return uid ?: if (!localEndpointAmbiguous) localEndpointUid else null
    }

    // Sobrecarga para cuando srcAddr/dstAddr llegan como InetAddress (caso IPv4 nativo,
    // sin mapear a IPv6).
    private fun resolveSub(
        protocol: Int,
        srcAddr: InetAddress,
        srcPort: Int,
        dstAddr: InetAddress,
        dstPort: Int,
        path: String?
    ): Int? = resolveSub(protocol, srcAddr.address, srcPort, dstAddr.address, dstPort, path)

    /**
     * Decodifica una dirección tal como aparece en /proc/net/{tcp,udp}[6]:
     * texto hex en el orden en que el kernel la escribió (little-endian del
     * host, por palabras de 32 bits), y la convierte a network byte order
     * (el mismo orden en que vienen las direcciones IP normales), replicando
     * el efecto de hex2bytes() + htonl() de ip.c.
     */
    private fun decodeKernelHexAddress(hex: String): ByteArray? {
        if (hex.length % 8 != 0) return null // debe ser múltiplo de 8 hex chars (una palabra de 32 bits)

        val wordCount = hex.length / 8
        val result = ByteArray(wordCount * 4)

        for (w in 0 until wordCount) {
            val wordHex = hex.substring(w * 8, w * 8 + 8)
            val b0 = wordHex.substring(0, 2).toIntOrNull(16) ?: return null
            val b1 = wordHex.substring(2, 4).toIntOrNull(16) ?: return null
            val b2 = wordHex.substring(4, 6).toIntOrNull(16) ?: return null
            val b3 = wordHex.substring(6, 8).toIntOrNull(16) ?: return null

            // El kernel escribe cada palabra de 32 bits en little-endian del host;
            // htonl() la convierte a big-endian (network byte order). El efecto neto
            // sobre los 4 bytes de una palabra es invertir su orden.
            val offset = w * 4
            result[offset] = b3.toByte()
            result[offset + 1] = b2.toByte()
            result[offset + 2] = b1.toByte()
            result[offset + 3] = b0.toByte()
        }

        return result
    }
}
